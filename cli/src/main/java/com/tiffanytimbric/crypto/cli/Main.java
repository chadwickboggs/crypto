package com.tiffanytimbric.crypto.cli;

import com.tiffanytimbric.crypto.api.Cryptosystem;
import io.reactivex.rxjava3.annotations.NonNull;
import io.reactivex.rxjava3.core.Scheduler;
import io.reactivex.rxjava3.core.Single;
import io.reactivex.rxjava3.internal.schedulers.ExecutorScheduler;
import joptsimple.OptionParser;
import joptsimple.OptionSet;

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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.IntStream;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;


/**
 * This class implements command-line access to encryption/decryption.  The
 * cryptosystem it should use must be specified as a command line parameter.
 * <p>
 * <b>Presently Supported Cryptosystems:</b> NOOP, XOR, NTRU
 * <p>
 * Input gets read from stdin.  Output gets written to stdout.  Encryption
 * output may be BaseN encoded.  Decryption input may be BaseN decoded.
 */
public final class Main {

    public static final String PF_CRYPTOSYSTEMS_CLASSNAME = "crypto.cryptosystem.%s.classname";
    private static final String USAGE_FILENAME_FORMAT = "usage-%s.txt";
    private static final String CONFIG_FILENAME = "config.properties";
    private static final String PN_CRYPTOSYSTEM_NAMES = "crypto.cryptosystem_names";
    private static final int DEFAULT_THREAD_COUNT = 1;

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
    public static void main( @Nonnull final String... args ) {
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
                        if ( config.baseNDecodeInput() ) {
                            inputList.addAll(
                                baseNDecode(
                                    inputTextChunks(
                                        config.chunkSize(), config.threadCount(), config.baseNDecodeInput(),
                                        config.baseN(), inputStreamReader
                                    ),
                                    config.baseN()
                                )
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
                        if ( !isEmpty( outputList ) ) {
                            if ( config.baseNEncodeOutput() ) {
                                writeTextOutputList(
                                    baseNEncode( outputList, config.baseN() ),
                                    outputStreamWriter
                                );
                            }
                            else {
                                writeOutputList( outputList, bufferedOutputStream );
                            }
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

    @Nonnull
    private static List<String> baseNEncode( @Nonnull final List<byte[]> bytes, int baseN ) {
        switch ( BaseN.forValue( baseN ) ) {
            case Sixteen -> {
                return Base16Util.encode( bytes );
            }
            case ThirtyTwo -> {
                return Base32Util.encode( bytes );
            }
            case SixtyFour -> {
                return Base64Util.encode( bytes );
            }
            default -> {
                exit( ExitCode.INVALID_ARGUMENT );

                return new ArrayList<>();
            }
        }
    }

    @Nonnull
    private static List<byte[]> baseNDecode( @Nonnull final List<String> texts, int baseN ) {
        switch ( BaseN.forValue( baseN ) ) {
            case Sixteen -> {
                return Base16Util.decode( texts );
            }
            case ThirtyTwo -> {
                return Base32Util.decode( texts );
            }
            case SixtyFour -> {
                return Base64Util.decode( texts );
            }
            default -> {
                exit( ExitCode.INVALID_ARGUMENT );

                return new ArrayList<>();
            }
        }
    }

    @Nonnull
    private static Config loadConfig( @Nonnull final OptionSet options ) throws ValidationException {
        final Action action = getAction( options );

        if ( Action.INFO.equals( action ) && !options.has( "c" ) ) {
            System.out.println( usageMessage( "crypto" ) );

            exit( ExitCode.SUCCESS );
        }

        if ( !options.has( "c" ) && !options.has( "cryptosystem" ) ) {
            exit( ExitCode.MISSING_CLI_ARGUMENTS );
        }
        final String cryptosystemName = String.valueOf( options.valueOf( "c" ) );
        if ( Action.INFO.equals( action ) ) {
            System.out.println( usageMessage( cryptosystemName ) );

            exit( ExitCode.SUCCESS );
        }
        boolean isBaseNEncode = isBaseNEncode( options );
        boolean isBaseNDecode = isBaseNDecode( options );
        int baseN = getBaseN( options );
        final Cryptosystem cryptosystem = loadCryptosystems(
            isBaseNEncode, isBaseNDecode, baseN
        ).get( cryptosystemName );
        if ( cryptosystem == null ) {
            throw new ValidationException( String.format(
                "Specified cryptosystem not found.  Specified Cryptosystem: \"%s\"", cryptosystemName
            ) );
        }

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

        return new Config(
            action,
            cryptosystem, Action.ENCRYPT.equals( action )
            ? cryptosystem.getChunkSizeEncrypt() : cryptosystem.getChunkSizeDecrypt(),
            threadCount,
            isBaseNDecode,
            isBaseNEncode,
            baseN,
            options.has( "x" ) || options.has( "rxjava" )
        );
    }

    private static int getBaseN( @Nonnull final OptionSet options ) {
        if ( options.has( "b" ) ) {
            return Integer.parseInt( String.valueOf( options.valueOf( "b" ) ) );
        }

        return 64;
    }

    @Nonnull
    private static Map<String, Cryptosystem> loadCryptosystems(
        boolean isBaseNEncode, boolean isBaseNDecode, int baseN
    ) {
        final Map<String, Cryptosystem> cryptosystems = new HashMap<>();
        try {
            final Properties properties = new Properties();
            properties.load( Main.class.getClassLoader().getResourceAsStream( CONFIG_FILENAME ) );
            final String crytosystemNames = properties.getProperty( PN_CRYPTOSYSTEM_NAMES );
            Arrays.stream( crytosystemNames.split( "\\," ) ).forEach( cryptosystemName -> {
                try {
                    final String cryptosystemClassname = properties.getProperty( String.format(
                        PF_CRYPTOSYSTEMS_CLASSNAME, cryptosystemName
                    ) );

                    final Cryptosystem cryptosystem = (Cryptosystem) Main.class.getClassLoader()
                        .loadClass( cryptosystemClassname ).getConstructor().newInstance();
                    cryptosystem.init( isBaseNEncode, isBaseNDecode, baseN );
                    cryptosystems.put( cryptosystemName, cryptosystem );
                }
                catch ( Throwable t ) {
                    exit( t );
                }
            } );
        }
        catch ( Throwable t ) {
            exit( t );
        }

        return cryptosystems;
    }

    @Nullable
    private static Action getAction( @Nonnull final OptionSet options ) {
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
        @Nonnull final List<String> outputList,
        @Nonnull final OutputStreamWriter outputStreamWriter
    ) {
        outputList.forEach( text -> writeTextOutput( text, outputStreamWriter ) );
    }

    private static void writeOutputList(
        @Nonnull final List<byte[]> outputList,
        @Nonnull final OutputStream outputStream
    ) {
        outputList.forEach( bytes -> writeOutput( bytes, outputStream ) );
    }

    private static void writeTextOutput(
        @Nonnull final String text, @Nonnull final OutputStreamWriter outputStreamWriter
    ) {
        try {
            outputStreamWriter.write( text );
        }
        catch ( IOException e ) {
            exit( e );
        }
    }

    private static void writeOutput(
        @Nonnull final byte[] bytes, @Nonnull final OutputStream outputStream
    ) {
        try {
            outputStream.write( bytes );
        }
        catch ( IOException e ) {
            exit( e );
        }
    }

    private static boolean isBaseNEncode( @Nonnull final OptionSet options ) {
        return (options.has( "e" ) || options.has( "encrypt" ))
            && (options.has( "b" ) || options.has( "baseN" ));
    }

    private static boolean isBaseNDecode( @Nonnull final OptionSet options ) {
        return (options.has( "d" ) || options.has( "decrypt" ))
            && (options.has( "b" ) || options.has( "baseN" ));
    }

    @Nonnull
    public static String usageMessage( String cryptosystemName ) {
        try (
            final InputStream inputStream = Main.class.getClassLoader().getResourceAsStream(
                getUsageFilename( cryptosystemName )
            )
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

    public static void exit( @Nonnull final Throwable t ) {
        t.printStackTrace();

        exit( ExitCode.EXCEPTION.ordinal(), t.getMessage() );
    }

    public static void exit( @Nonnull final ExitCode exitCode ) {
        exit( exitCode.ordinal(), exitCode.getMessage() );
    }

    public static void exit( int status, @Nonnull final String message ) {
        if ( status != 0 ) {
            System.err.println( message );
            System.err.println( usageMessage( "crypto" ) );
        }

        System.exit( status );
    }

    public static String getUsageFilename( String cryptosystemName ) {
        return String.format( USAGE_FILENAME_FORMAT, cryptosystemName );
    }

    @Nonnull
    private static List<byte[]> inputBinaryChunks(
        int chunkSize, int chunkCount, @Nonnull final InputStream inputStream
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


    @Nonnull
    private static byte[] inputBinaryChunk( int chunkSize, @Nonnull final InputStream inputStream ) {
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


    @Nonnull
    private static List<String> inputTextChunks(
        int chunkSize, int chunkCount, boolean baseNDecodeInput, int baseN,
        @Nonnull final InputStreamReader inputStreamReader
    ) {
        final List<String> cypherTexts = new ArrayList<>();
        IntStream.rangeClosed( 1, chunkCount ).forEachOrdered( count -> {
            final String cypherText = inputTextChunk( chunkSize, baseNDecodeInput, baseN, inputStreamReader );
            if ( cypherText.length() == 0 ) {
                return;
            }

            cypherTexts.add( cypherText );
        } );

        return cypherTexts;
    }

    @Nonnull
    private static String inputTextChunk(
        int chunkSize, boolean baseNDecodeInput, int baseN, @Nonnull final InputStreamReader inputStreamReader
    ) {
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
                buf.append(
                    new String(
                        StandardCharsets.UTF_8.encode( charBuffer ).array(),
                        StandardCharsets.UTF_8
                    ).replaceAll( "\\=", "" )
                );

                char currentChar = charBuf[numCharsRead - 1];
                if ( baseNDecodeInput ) {
                    if ( 16 == baseN && buf.length() == chunkSize ) {
                        break;
                    }
                    else if ( 32 == baseN && currentChar == '=' ) {
                        break;
                    }
                    else if ( 64 == baseN && currentChar == '=' && lastChar == '=' ) {
                        break;
                    }
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

    @Nonnull
    private static synchronized InputStreamReader getInputStreamReader( @Nonnull InputStream inputStream ) {
        if ( inputStreamReader == null ) {
            inputStreamReader = new InputStreamReader( getBufferedInputStream( inputStream ) );
        }

        return inputStreamReader;
    }

    private static synchronized BufferedInputStream getBufferedInputStream(
        @Nonnull final InputStream inputStream
    ) {
        if ( bufferedInputStream == null ) {
            bufferedInputStream = new BufferedInputStream( inputStream );
        }

        return bufferedInputStream;
    }

    @Nonnull
    private static synchronized OutputStreamWriter getOutputStreamWriter(
        @Nonnull final OutputStream outputStream
    ) {
        if ( outputStreamWriter == null ) {
            outputStreamWriter = new OutputStreamWriter( getBufferedOutputStream( outputStream ) );
        }

        return outputStreamWriter;
    }

    @Nonnull
    private static synchronized BufferedOutputStream getBufferedOutputStream(
        @Nonnull final OutputStream outputStream
    ) {
        if ( bufferedOutputStream == null ) {
            bufferedOutputStream = new BufferedOutputStream( outputStream );
        }

        return bufferedOutputStream;
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

    @Nonnull
    private static List<byte[]> processChunks(
        @Nonnull final List<byte[]> inputList, @Nonnull final Config config
    ) {
        if ( config.useRxJava() ) {
            return processChunksConcurrentlyUsingRxJava( inputList, config );
        }

        return processChunksConcurrently( inputList, config );
    }

    @Nonnull
    private static List<byte[]> processChunksConcurrently(
        @NonNull final List<byte[]> inputList, @Nonnull final Config config
    ) {
        final Action action = config.action();
        final Cryptosystem cryptosystem = config.cryptosystem();
        final byte[][] outputs = new byte[inputList.size()][];

        try (
            final AutoCloseableExecutorServiceHolder autoCloseableExecutorServiceHolder =
                new AutoCloseableExecutorServiceHolder(
                    Executors.newFixedThreadPool( config.threadCount() )
                )
        ) {
            final ExecutorService executorService = autoCloseableExecutorServiceHolder.executorService();
            IntStream.range( 0, inputList.size() ).forEachOrdered( i -> {
                final byte[][] inputs = inputList.toArray( new byte[inputList.size()][] );
                final int index = i;
                if ( action.equals( Action.DECRYPT ) ) {
                    executorService.submit( () -> {
                            try {
                                outputs[index] = cryptosystem.decrypt( inputs[index] );
                            }
                            catch ( Throwable t ) {
                                exit( t );
                            }
                        }
                    );
                }
                else if ( action.equals( Action.ENCRYPT ) ) {
                    executorService.submit( () -> {
                            try {
                                outputs[index] = cryptosystem.encrypt( inputs[index] );
                            }
                            catch ( Throwable t ) {
                                exit( t );
                            }
                        }
                    );
                }
            } );
        }

        return Arrays.asList( outputs );
    }

    @Nonnull
    private static List<byte[]> processChunksConcurrentlyUsingRxJava(
        @NonNull final List<byte[]> inputList, @Nonnull final Config config
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

    @Nonnull
    private static synchronized OptionParser getCliParser() {
        final OptionParser parser = new OptionParser( "+c:?e?d?b:?k:?t:?x?h?u?p:?" );

        parser.recognizeAlternativeLongOptions( true );
        parser.accepts( "cryptosystem" );
        parser.accepts( "encrypt" );
        parser.accepts( "decrypt" );
        parser.accepts( "baseN" ).withRequiredArg().defaultsTo( "64" );
        parser.accepts( "rxjava" );
        parser.accepts( "key" ).withRequiredArg().defaultsTo( "64" );
        parser.accepts( "threads" ).withRequiredArg().defaultsTo( String.valueOf( DEFAULT_THREAD_COUNT ) );
        parser.accepts( "help" );
        parser.accepts( "usage" );
        parser.accepts( "usage_filename" );

        return parser;
    }


    public enum CryptosystemName {
        NOOP, XOR, NTRU
    }


    public enum Action {
        INFO, ENCRYPT, DECRYPT
    }


    public enum BaseN {
        Sixteen( 16 ), ThirtyTwo( 32 ), SixtyFour( 64 );

        private final int value;

        BaseN( int value ) {
            this.value = value;
        }

        @Nonnull
        public static BaseN forValue( int value ) {
            if ( 16 == value ) {
                return Sixteen;
            }
            if ( 32 == value ) {
                return ThirtyTwo;
            }
            if ( 64 == value ) {
                return SixtyFour;
            }

            throw new IllegalArgumentException( String.format(
                "Unsupported value of base encoded provided.  Supported values: 16, 32, 64, Provided Value: %d",
                value
            ) );
        }

        public int getValue() {
            return value;
        }
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

        ExitCode( @Nonnull final String message ) {
            this.message = message;
        }

        @Nonnull
        public String getMessage() {
            return message;
        }
    }


    /**
     * This record exists because ExecutorService does not implement AutoCloseable
     * Java version 19.
     */
    private record AutoCloseableExecutorServiceHolder(
        @Nonnull ExecutorService executorService
    ) implements AutoCloseable {

        @Override
        @Nonnull
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
