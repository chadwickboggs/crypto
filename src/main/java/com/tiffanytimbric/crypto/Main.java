package com.tiffanytimbric.crypto;

import com.tiffanytimbric.crypto.nooputil.NoopUtil;
import com.tiffanytimbric.crypto.ntrutil.NtrUtil;
import com.tiffanytimbric.crypto.xorutil.XorUtil;
import io.reactivex.rxjava3.annotations.NonNull;
import io.reactivex.rxjava3.core.Scheduler;
import io.reactivex.rxjava3.core.Single;
import io.reactivex.rxjava3.internal.schedulers.ExecutorScheduler;
import joptsimple.OptionParser;
import joptsimple.OptionSet;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.StringWriter;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.IntStream;


/**
 * This class implements command-line access to encryption/decryption.  The
 * cryptosystem it should use must be specified as a command line parameter.
 * <p>
 * <b>Presently Supported Cryptosystems:</b> NOOP, XOR, NTRU
 * <p>
 * Input gets read from stdin.  Output gets written to stdout.  Encryption
 * output may be Base64 encoded.  Decryption input may be Base64 encoded.
 */
public final class Main {

    private static final String USAGE_FILENAME = "usage-cryptosystem.txt";
    private static final int DEFAULT_THREAD_COUNT = 1;
    private static String usageFilename = USAGE_FILENAME;

    private static volatile BufferedInputStream bufferedInputStream = null;
    private static volatile InputStreamReader inputStreamReader = null;
    private static volatile BufferedOutputStream bufferedOutputStream = null;
    private static volatile OutputStreamWriter outputStreamWriter = null;


    /**
     * Executes this program which reads its config, parses its command-line arguments,
     * then executes its logic.  This programs logic consists of reading input from stdin,
     * running the specified cryptosystem's encrypt or decrypt on it, then printing the
     * resulting output to stdout.  Input is read in, processed, and output in lists of
     * chunks.  The size of each chunk equals the key size which was specified or configured
     * for specified cryptosystem.  The list of chunks equals the thread count which was
     * specified or configured.
     * <p>
     * <b>Program Steps</b>
     * <ol>
     *     <li>Setup: Read config, parse command-line arguments.</li>
     *     <li>Execute program logic.
     *      <ol>
     *          <li>Input one threadCount sized list of chunks.</li>
     *          <li>Process (encrypt/decrypt) the chunks.</li>
     *          <li>Output the processed list of chunks.</li>
     *      </ol>
     *     </li>
     * </ol>
     *
     * @param args command-line arguments.
     */
    public static void main( @NotNull final String... args ) {
        if ( args.length == 0 ) {
            exit( ExitCode.MISSING_CLI_ARGUMENTS );
        }

        try {
            //
            // 1. Setup: Read config, parse command-line arguments.
            //
            final Config config = loadConfig( getCliParser().parse( args ) );

            //
            // 2. Execute program logic.
            //
            try (
                final BufferedInputStream bufferedInputStream = getBufferedInputStream( System.in );
                final InputStreamReader inputStreamReader = getInputStreamReader( bufferedInputStream )
            ) {
                try (
                    final BufferedOutputStream bufferedOutputStream = getBufferedOutputStream( System.out );
                    final OutputStreamWriter outputStreamWriter = getOutputStreamWriter( bufferedOutputStream )
                ) {
                    while ( true ) {
                        //
                        // 2.1. Input one threadCount sized list of chunks.
                        //
                        final List<byte[]> inputList = new ArrayList<>();
                        if ( config.base64DecodeInput() ) {
                            inputList.addAll(
                                Base64Util.decode( inputTextChunks( config.threadCount(), inputStreamReader ) )
                            );
                        }
                        else {
                            inputList.addAll(
                                inputBinaryChunks( config.chunkSize(), config.threadCount(), bufferedInputStream )
                            );
                        }
                        if ( isEmpty( inputList ) ) {
                            break;
                        }
                        validateInputList( inputList );

                        //
                        // 2.2. Process (encrypt/decrypt) the chunks.
                        //
                        final List<byte[]> outputList = processChunks( inputList, config );
                        validateOutputList( outputList );

                        //
                        // 2.3. Output the processed list of chunks.
                        //
                        if ( config.base64EncodeOutput() ) {
                            writeTextOutputList( Base64Util.encode( outputList ), outputStreamWriter );
                        }
                        else {
                            writeOutputList( outputList, bufferedOutputStream );
                        }

                        outputStreamWriter.flush();
                        bufferedOutputStream.flush();
                        inputList.clear();
                    }
                }
            }
        }
        catch ( final Throwable t ) {
            exit( t );
        }

        exit( ExitCode.SUCCESS );
    }

    @NotNull
    private static Config loadConfig( @NotNull final OptionSet options ) {
        final Action action = getAction( options );

        if ( Action.INFO.equals( action ) ) {
            System.out.println( usageMessage() );

            exit( ExitCode.SUCCESS );
        }

        if ( !options.has( "c" ) && !options.has( "cryptosystem" ) ) {
            exit( ExitCode.MISSING_CLI_ARGUMENTS );
        }
        final String cryptosystemName = String.valueOf( options.valueOf( "c" ) );
        final Cryptosystem cryptosystem = getCryptosystem( cryptosystemName );

        if ( options.has( "k" ) || options.has( "key" ) ) {
            if ( cryptosystemName.equals( CryptosystemName.NTRU.name() ) ) {
                exit( ExitCode.INVALID_ARGUMENT );
            }

            int keySize = Integer.parseInt( options.valueOf( "k" ).toString() );
            cryptosystem.setChunkSizeEncrypt( keySize );
            cryptosystem.setChunkSizeDecrypt( keySize );
        }

        int threadCount = DEFAULT_THREAD_COUNT;
        if ( options.has( "t" ) || options.has( "threads" ) ) {
            threadCount = Integer.parseInt( options.valueOf( "t" ).toString() );
        }

        int chunkSize = Action.ENCRYPT.equals( action )
            ? cryptosystem.getChunkSizeEncrypt() : cryptosystem.getChunkSizeDecrypt();

        boolean base64DecodeInput = isBase64Decode( options );
        boolean base64EncodeOutput = isBase64Encode( options );

        boolean useRxJava = options.has( "x" ) || options.has( "rxjava" );

        return new Config(
            action, cryptosystem, chunkSize, threadCount, base64DecodeInput, base64EncodeOutput, useRxJava
        );
    }

    @Nullable
    private static Action getAction( @NotNull final OptionSet options ) {
        if ( options.has( "?" ) || options.has( "h" ) || options.has( "u" )
            || options.has( "help" ) || options.has( "usage" ) ) {
            return Action.INFO;
        }

        if ( options.has( "d" ) || options.has( "decrypt" ) ) {
            return Action.DECRYPT;
        }

        if ( options.has( "e" ) || options.has( "encrypt" ) ) {
            return Action.ENCRYPT;
        }

        exit( ExitCode.MISSING_CLI_ARGUMENTS );

        return null;
    }

    private static void validateOutputList( @Nullable final List<byte[]> outputList ) throws ValidationException {
        if ( isEmpty( outputList ) ) {
            return;
        }

        if ( outputList.stream().anyMatch( Objects::isNull ) ) {
            throw new ValidationException( "Invalid null output value found.  Each output value must be non-null." );
        }
        if ( outputList.stream().map( Arrays::asList ).anyMatch( List::isEmpty ) ) {
            throw new ValidationException( "Invalid empty output value found.  Each output value must be non-empty." );
        }
    }

    private static void writeTextOutputList(
        @NotNull final List<String> outputList,
        @NotNull final OutputStreamWriter outputStreamWriter
    ) {
        outputList.forEach( text -> writeTextOutput( text, outputStreamWriter ) );
    }

    private static void writeOutputList(
        @NotNull final List<byte[]> outputList,
        @NotNull final OutputStream outputStream
    ) {
        outputList.forEach( bytes -> writeOutput( bytes, outputStream ) );
    }

    private static void writeTextOutput(
        @NotNull final String text, @NotNull final OutputStreamWriter outputStreamWriter
    ) {
        try {
            outputStreamWriter.write( text );
        }
        catch ( IOException e ) {
            exit( e );
        }
    }

    private static void writeOutput(
        @NotNull final byte[] bytes, @NotNull final OutputStream outputStream
    ) {
        try {
            outputStream.write( bytes );
        }
        catch ( IOException e ) {
            exit( e );
        }
    }

    private static boolean isBase64Encode( @NotNull final OptionSet options ) {
        return (options.has( "e" ) || options.has( "encrypt" ))
            && (options.has( "b" ) || options.has( "base64" ));
    }

    private static boolean isBase64Decode( @NotNull final OptionSet options ) {
        return (options.has( "d" ) || options.has( "decrypt" ))
            && (options.has( "b" ) || options.has( "base64" ));
    }

    @NotNull
    public static String usageMessage() {
        try (
            final InputStream inputStream = NtrUtil.class.getClassLoader().getResourceAsStream( getUsageFilename() )
        ) {
            if ( inputStream == null ) {
                exit( ExitCode.MISSING_RESOURCE );

                return "";
            }

            try ( final BufferedReader reader = new BufferedReader( new InputStreamReader( inputStream ) ) ) {
                try ( final StringWriter stringWriter = new StringWriter() ) {
                    try ( final BufferedWriter writer = new BufferedWriter( stringWriter ) ) {
                        String line;
                        while ( (line = reader.readLine()) != null ) {
                            writer.write( line );
                            writer.newLine();
                        }

                        writer.flush();
                    }

                    stringWriter.flush();

                    return stringWriter.toString();
                }
            }
        }
        catch ( Throwable t ) {
            exit( t );
        }

        return "";
    }

    public static void exit( @NotNull final Throwable t ) {
        t.printStackTrace();

        exit( ExitCode.EXCEPTION.ordinal(), t.getMessage() );
    }

    public static void exit( @NotNull final ExitCode exitCode ) {
        exit( exitCode.ordinal(), exitCode.getMessage() );
    }

    public static void exit( int status, @NotNull final String message ) {
        if ( status != 0 ) {
            System.err.println( message );
            System.err.println( usageMessage() );
        }

        System.exit( status );
    }

    public static String getUsageFilename() {
        return usageFilename;
    }

    public static void setUsageFilename( String usageFilename ) {
        Main.usageFilename = usageFilename;
    }

    @NotNull
    private static List<byte[]> inputBinaryChunks(
        int chunkSize, int chunkCount, @NotNull final InputStream inputStream
    ) {
        final List<byte[]> cypherTexts = new ArrayList<>();
        IntStream.rangeClosed( 1, chunkCount ).forEachOrdered( count -> {
            byte[] input = inputBinaryChunk( chunkSize, inputStream );
            if ( input.length > 0 ) {
                cypherTexts.add( input );
            }
        } );

        return cypherTexts;
    }


    @NotNull
    private static byte[] inputBinaryChunk( int chunkSize, @NotNull final InputStream inputStream ) {
        try ( final ByteArrayOutputStream outputStream = new ByteArrayOutputStream() ) {
            int totalRead = 0;
            do {
                byte[] value = new byte[chunkSize - totalRead];
                int numRead = inputStream.read( value );
                if ( numRead < 0 ) {
                    return outputStream.toByteArray();
                }

                totalRead += numRead;

                outputStream.write( value, 0, numRead );
                outputStream.flush();
            }
            while ( totalRead < chunkSize );

            return outputStream.toByteArray();
        }
        catch ( IOException e ) {
            throw new RuntimeException( e );
        }
    }


    @NotNull
    private static List<String> inputTextChunks(
        int chunkCount, @NotNull final InputStreamReader inputStreamReader
    ) {
        final List<String> cypherTexts = new ArrayList<>();
        IntStream.rangeClosed( 1, chunkCount ).forEachOrdered( count -> {
            String cypherText = inputTextChunk( inputStreamReader );
            if ( cypherText.length() == 0 ) {
                return;
            }

            cypherTexts.add( cypherText );
        } );

        return cypherTexts;
    }

    @NotNull
    private static String inputTextChunk( @NotNull final InputStreamReader inputStreamReader ) {
        final StringBuilder buf = new StringBuilder();
        try {
            char[] charBuf = new char[1];
            int numCharsRead;
            char lastChar = Character.MIN_VALUE;
            do {
                while ( (numCharsRead = inputStreamReader.read( charBuf )) == 0 ) {
                    // Ignore.
                }
                if ( numCharsRead < 0 ) {
                    break;
                }

                final CharBuffer charBuffer = CharBuffer.wrap( Arrays.copyOf( charBuf, numCharsRead ) );
                buf.append( new String(
                    StandardCharsets.UTF_8.encode( charBuffer ).array(),
                    StandardCharsets.UTF_8
                ) );

                char currentChar = charBuf[numCharsRead - 1];
                if ( currentChar == '=' && lastChar == '=' ) {
                    break;
                }
                lastChar = currentChar;
            }
            while ( true );
        }
        catch ( IOException e ) {
            throw new RuntimeException( e );
        }

        return buf.toString();
    }

    @NotNull
    private static synchronized InputStreamReader getInputStreamReader( @NotNull InputStream inputStream ) {
        if ( inputStreamReader == null ) {
            inputStreamReader = new InputStreamReader( getBufferedInputStream( inputStream ) );
        }

        return inputStreamReader;
    }

    private static synchronized BufferedInputStream getBufferedInputStream(
        @NotNull final InputStream inputStream
    ) {
        if ( bufferedInputStream == null ) {
            bufferedInputStream = new BufferedInputStream( inputStream );
        }

        return bufferedInputStream;
    }

    @NotNull
    private static synchronized OutputStreamWriter getOutputStreamWriter(
        @NotNull final OutputStream outputStream
    ) {
        if ( outputStreamWriter == null ) {
            outputStreamWriter = new OutputStreamWriter( getBufferedOutputStream( outputStream ) );
        }

        return outputStreamWriter;
    }

    @NotNull
    private static synchronized BufferedOutputStream getBufferedOutputStream(
        @NotNull final OutputStream outputStream
    ) {
        if ( bufferedOutputStream == null ) {
            bufferedOutputStream = new BufferedOutputStream( outputStream );
        }

        return bufferedOutputStream;
    }

    @NotNull
    private static Cryptosystem getCryptosystem( @NotNull final String cryptosystemName ) {
        Cryptosystem cryptosystem = null;
        switch ( CryptosystemName.valueOf( cryptosystemName ) ) {
            case NOOP -> cryptosystem = new NoopUtil();
            case XOR -> cryptosystem = new XorUtil();
            case NTRU -> cryptosystem = new NtrUtil();
            default -> exit( ExitCode.UNRECOGNIZED_ARGUMENT_VALUE );
        }

        return cryptosystem;
    }

    private static void validateInputList(
        @Nullable final List<byte[]> inputList
    ) throws ValidationException {
        if ( !isEmpty( inputList ) && inputList.get( 0 ).length > 0 ) {
            return;
        }

        throw new ValidationException(
            "Invalid input data.  The input data's length must be greater than zero."
        );
    }

    private static boolean isEmpty( @Nullable List<byte[]> inputList ) {
        return inputList == null || inputList.isEmpty() || inputList.get( 0 ) == null;
    }

    @NotNull
    private static List<byte[]> processChunks(
        @NotNull final List<byte[]> inputList, @NotNull final Config config
    ) {
        if ( config.useRxJava() ) {
            return processChunksConcurrentlyUsingRxJava( inputList, config );
        }

        return processChunksConcurrently( inputList, config );
    }

    @NotNull
    private static List<byte[]> processChunksConcurrently(
        @NonNull final List<byte[]> inputList, @NotNull final Config config
    ) {
        final Action action = config.action();
        final Cryptosystem cryptosystem = config.cryptosystem();

        final byte[][] outputs = new byte[inputList.size()][];

        try (
            final AutoCloseableExecutorServiceHolder autoCloseableExecutorServiceHolder =
                new AutoCloseableExecutorServiceHolder( Executors.newFixedThreadPool( config.threadCount() ) )
        ) {
            final ExecutorService executorService = autoCloseableExecutorServiceHolder.executorService();
            IntStream.range( 0, inputList.size() ).forEachOrdered( i -> {
                final byte[][] inputs = inputList.toArray( new byte[inputList.size()][] );
                final int index = i;
                if ( action.equals( Action.DECRYPT ) ) {
                    executorService.submit( () ->
                        outputs[index] = cryptosystem.decrypt( inputs[index] )
                    );
                }
                else if ( action.equals( Action.ENCRYPT ) ) {
                    executorService.submit( () ->
                        outputs[index] = cryptosystem.encrypt( inputs[index] )
                    );
                }
            } );
        }

        return Arrays.asList( outputs );
    }

    @NotNull
    private static List<byte[]> processChunksConcurrentlyUsingRxJava(
        @NonNull final List<byte[]> inputList, @NotNull final Config config
    ) {
        final Action action = config.action();
        final Cryptosystem cryptosystem = config.cryptosystem();

        final byte[][] outputs = new byte[inputList.size()][];

        try (
            final AutoCloseableExecutorServiceHolder autoCloseableExecutorServiceHolder =
                new AutoCloseableExecutorServiceHolder( Executors.newFixedThreadPool( config.threadCount() ) )
        ) {
            final ExecutorService executorService = autoCloseableExecutorServiceHolder.executorService();
            final ExecutorScheduler executorScheduler = new ExecutorScheduler(
                executorService, false, true
            );

            IntStream.range( 0, inputList.size() ).forEachOrdered( i -> {
                final byte[][] inputs = inputList.toArray( new byte[inputList.size()][] );
                final int index = i;
                if ( action.equals( Action.DECRYPT ) ) {
                    executorScheduler.scheduleDirect( () -> {
                        try {
                            outputs[index] = cryptosystem.decrypt( inputs[index] );
                        }
                        catch ( IOException e ) {
                            exit( e );
                        }
                    } );
                }
                else if ( action.equals( Action.ENCRYPT ) ) {
                    executorScheduler.scheduleDirect( () -> {
                        try {
                            outputs[index] = cryptosystem.encrypt( inputs[index] );
                        }
                        catch ( IOException e ) {
                            exit( e );
                        }
                    } );
                }
            } );

            final Scheduler.Worker worker = executorScheduler.createWorker();
            final Single<Scheduler.Worker> single = Single.just( worker );
            single.doOnError( Main::exit );
            executorScheduler.start();
            single.blockingSubscribe();
        }

        return Arrays.asList( outputs );
    }

    @NotNull
    private static synchronized OptionParser getCliParser() {
        final OptionParser parser = new OptionParser( "+c:?e?d?b?k:?t:?x?h?u?" );

        parser.recognizeAlternativeLongOptions( true );
        parser.accepts( "cryptosystem" );
        parser.accepts( "encrypt" );
        parser.accepts( "decrypt" );
        parser.accepts( "base64" );
        parser.accepts( "rxjava" );
        parser.accepts( "key" ).withRequiredArg().defaultsTo( String.valueOf( 64 ) );
        parser.accepts( "threads" ).withRequiredArg().defaultsTo( String.valueOf( DEFAULT_THREAD_COUNT ) );
        parser.accepts( "help" );
        parser.accepts( "usage" );

        return parser;
    }


    public enum CryptosystemName {
        NOOP, XOR, NTRU
    }


    public enum Action {
        INFO, ENCRYPT, DECRYPT
    }


    public enum ExitCode {
        SUCCESS( "Execution of this program completed successfully." ),
        MISSING_CLI_ARGUMENTS( "Some of the required command line arguments are missing." ),
        UNRECOGNIZED_ARGUMENT_VALUE( "Some command line arguments have unrecognized values." ),
        MISSING_RESOURCE(
            "A required resource expected to be found in this program's classpath was not found."
        ),
        EMPTY_INPUT( "Empty input was found were non-empty is required." ),
        INVALID_ARGUMENT( "Some command line arguments were given which are invalid." ),
        INTERRUPTED( "A processing thread was interrupted corrupting processing." ),
        EXCEPTION( "An unexpected exception has occurred." );

        private final String message;

        ExitCode( @NotNull final String message ) {
            this.message = message;
        }

        @NotNull
        public String getMessage() {
            return message;
        }
    }


    /**
     * This record exists because ExecutorService does not implement AutoCloseable
     * Java version 19.
     */
    private record AutoCloseableExecutorServiceHolder(
        @NotNull ExecutorService executorService
    ) implements AutoCloseable {

        @Override
        @NotNull
        public ExecutorService executorService() {
            return executorService;
        }

        @Override
        public void close() {
            executorService.shutdown();
            while ( !executorService.isTerminated() ) {
                try {
                    if ( !executorService.awaitTermination( Long.MAX_VALUE, TimeUnit.MILLISECONDS ) ) {
                        exit( ExitCode.INTERRUPTED );
                    }
                }
                catch ( InterruptedException e ) {
                    exit( e );
                }
            }

            if ( executorService instanceof AutoCloseable ) {
                try {
                    ((AutoCloseable) executorService).close();
                }
                catch ( Exception ignored ) {
                }
            }
        }
    }
}
