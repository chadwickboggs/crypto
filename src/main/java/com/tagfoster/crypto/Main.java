package com.tagfoster.crypto;

import com.tagfoster.crypto.nooputil.NoopUtil;
import com.tagfoster.crypto.ntrutil.NtrUtil;
import com.tagfoster.crypto.xorutil.XorUtil;
import io.reactivex.rxjava3.annotations.NonNull;
import io.reactivex.rxjava3.core.Scheduler;
import io.reactivex.rxjava3.core.Single;
import io.reactivex.rxjava3.internal.schedulers.ExecutorScheduler;
import joptsimple.OptionParser;
import joptsimple.OptionSet;
import org.jetbrains.annotations.NotNull;

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
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.IntStream;


/**
 * This class implements command-line access to encryption/decryption.  The
 * cryptosystem it should used must be specified as a command line parameter.
 * <br>
 * Presently Supported Cryptosystems: NOOP, XOR, NTRU
 * <br>
 * Input gets read from stdin.  Output gets written to stdout.  Encryption
 * output is Base64 encoded.  Decryption input is assumed to be Base64 encoded.
 */
public final class Main {

    private static final String USAGE_TXT_FILENAME = "usage-cryptosystem.txt";
    private static final int DEFAULT_THREAD_COUNT = 2;
    private static final int DEFAULT_CHUNK_SIZE = 64;
    private static int threadCount = DEFAULT_THREAD_COUNT;
    private static int chunkSize = DEFAULT_CHUNK_SIZE;
    private static volatile BufferedInputStream bufferedInputStream = null;
    private static volatile InputStreamReader inputStreamReader = null;
    private static volatile BufferedOutputStream bufferedOutputStream = null;
    private static volatile OutputStreamWriter outputStreamWriter = null;

    public static void main( @NotNull final String... args ) throws Exception {
        if ( args.length == 0 ) {
            System.err.println( usageMessage() );

            exit( ExitCode.MISSING_CLI_ARGUMENTS.ordinal() );
        }

        try {
            final OptionSet options = getCliParser().parse( args );

            if ( options.has( "?" ) || options.has( "h" ) || options.has( "u" )
                || options.has( "help" ) || options.has( "usage" ) ) {
                System.out.println( usageMessage() );

                exit( ExitCode.SUCCESS.ordinal() );
            }

            if ( options.has( "k" ) || options.has( "key" ) ) {
                chunkSize = Integer.parseInt( options.valueOf( "k" ).toString() );
            }

            if ( !options.has( "c" ) && !options.has( "cryptosystem" ) ) {
                exit( ExitCode.MISSING_CLI_ARGUMENTS.ordinal() );
            }
            final String cryptosystemName = String.valueOf( options.valueOf( "c" ) );
            final Cryptosystem cryptosystem = getCryptosystem( cryptosystemName, chunkSize );

            if ( options.has( "t" ) || options.has( "threads" ) ) {
                threadCount = Integer.parseInt( options.valueOf( "t" ).toString() );
            }

            boolean didRead = false;


            ;
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
                        // 1. Input one threadCount sized list of chunks.
                        //
                        final List<byte[]> inputList = new ArrayList<>();
                        if ( isBase64Decode( cryptosystemName, options ) ) {
                            inputList.addAll( Base64Util.decode( inputTextChunks( threadCount, inputStreamReader ) ) );
                        }
                        else {
                            inputList.addAll( inputBinaryChunks( chunkSize, threadCount, bufferedInputStream ) );
                        }

                        didRead = validateInput( inputList, didRead );

                        //
                        // 2. Process (encrypt/decrypt) the chunks.
                        //
                        List<byte[]> outputList = processChunks( inputList, threadCount, cryptosystem, options );

                        //
                        // 3. Output the processed chunks.
                        //
                        if ( isBase64Encode( cryptosystemName, options ) ) {
                            final List<String> encodedOutputList = Base64Util.encode( outputList );
                            writeTextOutputList( encodedOutputList, outputStreamWriter );
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

        exit( ExitCode.SUCCESS.ordinal() );
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

    private static boolean isBase64Encode(
        @NotNull final String cryptosystemName, @NotNull final OptionSet options
    ) {
        if (
            (options.has( "e" ) || options.has( "encrypt" )) && (
                options.has( "b" ) || options.has( "base64" ) ||
                    cryptosystemName.equals( CryptosystemName.NTRU.name() )
            ) ) {
            return true;
        }

        return false;
    }

    private static boolean isBase64Decode(
        @NotNull final String cryptosystemName, @NotNull final OptionSet options
    ) {
        if (
            (options.has( "d" ) || options.has( "decrypt" )) && (
                options.has( "b" ) || options.has( "base64" ) ||
                    cryptosystemName.equals( CryptosystemName.NTRU.name() )
            ) ) {
            return true;
        }

        return false;
    }

    @NotNull
    public static String usageMessage() throws Exception {
        try (
            final InputStream inputStream = NtrUtil.class.getClassLoader().getResourceAsStream( USAGE_TXT_FILENAME )
        ) {
            if ( inputStream == null ) {
                exit( ExitCode.MISSING_RESOURCE.ordinal() );

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
    }

    public static void exit( @NotNull final Throwable t ) {
        t.printStackTrace();

        exit( ExitCode.EXCEPTION.ordinal() );
    }

    public static void exit( int status ) {
        if ( status != 0 ) {
            try {
                System.err.println( usageMessage() );
            }
            catch ( Exception e ) {
                e.printStackTrace();
                status = 101;
            }
        }

        System.exit( status );
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
            if ( cypherText.length() <= 0 ) {
                return;
            }

            if ( cypherText.length() > 0 ) {
                cypherTexts.add( cypherText );
            }
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
                numCharsRead = inputStreamReader.read( charBuf );
                if ( numCharsRead < 0 ) {
                    break;
                }
                if ( numCharsRead > 0 ) {
                    buf.append( charBuf );
                    if ( charBuf[numCharsRead - 1] == '=' && lastChar == '=' ) {
                        break;
                    }
                    lastChar = charBuf[numCharsRead - 1];
                }
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
        if (outputStreamWriter == null) {
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
    private static Cryptosystem getCryptosystem(
        @NotNull final String cryptosystemName, int keySize
    ) {
        Cryptosystem cryptosystem = null;
        switch ( CryptosystemName.valueOf( cryptosystemName ) ) {
            case NOOP -> cryptosystem = new NoopUtil();
            case XOR -> cryptosystem = new XorUtil( keySize );
            case NTRU -> cryptosystem = new NtrUtil( keySize );
            default -> exit( ExitCode.UNRECOGNIZED_ARGUMENT_VALUE.ordinal() );
        }

        return cryptosystem;
    }

    private static boolean validateInput( List<byte[]> inputList, boolean didRead ) {
        if ( inputList.size() != 0 && inputList.get( 0 ) != null && inputList.get( 0 ).length != 0 ) {
            return true;
        }

        if ( didRead ) {
            exit( ExitCode.SUCCESS.ordinal() );
        }
        else {
            exit( ExitCode.EMPTY_INPUT.ordinal() );
        }

        return false;
    }

    @NotNull
    private static List<byte[]> processChunks(
        @NotNull final List<byte[]> inputList,
        int threadCount,
        @NotNull final Cryptosystem cryptosystem,
        @NotNull final OptionSet options
    ) throws InterruptedException {
        if ( options.has( "x" ) || options.has( "rxjava" ) ) {
            return processChunksConcurrentlyUsingRxJava( inputList, threadCount, cryptosystem, options );
        }

        return processChunksConcurrently( inputList, threadCount, cryptosystem, options );
    }

    @NotNull
    private static List<byte[]> processChunksConcurrently(
        @NonNull final List<byte[]> inputList,
        int threadCount,
        @NonNull final Cryptosystem cryptosystem,
        @NonNull final OptionSet options
    ) throws InterruptedException {
        final List<byte[]> outputs = new ArrayList<>( inputList.size() );

        try ( final ExecutorService executorService = Executors.newFixedThreadPool( threadCount ) ) {
            for ( int i = 0; i < inputList.size(); i++ ) {
                final List<byte[]> inputs = new ArrayList<>( inputList );
                final int index = i;

                if ( options.has( "e" ) || options.has( "encrypt" ) ) {
                    executorService.submit( () ->
                        outputs.add( cryptosystem.encrypt( inputs.get( index ) ) )
                    );
                }
                else if ( options.has( "d" ) || options.has( "decrypt" ) ) {
                    executorService.submit( () ->
                        outputs.add( cryptosystem.decrypt( inputs.get( index ) ) )
                    );
                }
            }

            executorService.shutdown();
            if ( !executorService.awaitTermination( Long.MAX_VALUE, TimeUnit.MILLISECONDS ) ) {
                exit( ExitCode.INTERRUPTED.ordinal() );
            }
        }

        return outputs;
    }

    @NotNull
    private static List<byte[]> processChunksConcurrentlyUsingRxJava(
        @NonNull final List<byte[]> inputList,
        int threadCount,
        @NonNull final Cryptosystem cryptosystem,
        @NonNull final OptionSet options
    ) throws InterruptedException {
        final List<byte[]> outputs = new ArrayList<>( inputList.size() );

        try ( final ExecutorService executorService = Executors.newFixedThreadPool( threadCount ) ) {
            final ExecutorScheduler executorScheduler = new ExecutorScheduler(
                executorService, false, true
            );

            for ( int i = 0; i < inputList.size(); i++ ) {
                final List<byte[]> inputs = new ArrayList<>( inputList );
                final int index = i;

                if ( options.has( "e" ) || options.has( "encrypt" ) ) {
                    executorScheduler.scheduleDirect( () -> {
                        try {
                            outputs.add( cryptosystem.encrypt( inputs.get( index ) ) );
                        }
                        catch ( IOException e ) {
                            exit( e );
                        }
                    } );
                }
                else if ( options.has( "d" ) || options.has( "decrypt" ) ) {
                    executorScheduler.scheduleDirect( () -> {
                        try {
                            outputs.add( cryptosystem.decrypt( inputs.get( index ) ) );
                        }
                        catch ( IOException e ) {
                            exit( e );
                        }
                    } );
                }
            }

            final Scheduler.Worker worker = executorScheduler.createWorker();
            final Single<Scheduler.Worker> single = Single.just( worker );
            single.doOnError( Main::exit );
            executorScheduler.start();
            single.blockingSubscribe();

            executorService.shutdown();
            if ( !executorService.awaitTermination( Long.MAX_VALUE, TimeUnit.MILLISECONDS ) ) {
                exit( ExitCode.INTERRUPTED.ordinal() );
            }
        }

        return outputs;
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
        parser.accepts( "key" ).withRequiredArg().defaultsTo( String.valueOf( DEFAULT_CHUNK_SIZE ) );
        parser.accepts( "threads" ).withRequiredArg().defaultsTo( String.valueOf( DEFAULT_THREAD_COUNT ) );
        parser.accepts( "help" );
        parser.accepts( "usage" );

        return parser;
    }


    public enum CryptosystemName {
        NOOP, XOR, NTRU
    }


    public enum ExitCode {
        SUCCESS, MISSING_CLI_ARGUMENTS, UNRECOGNIZED_ARGUMENT_VALUE, MISSING_RESOURCE, EMPTY_INPUT,
        INTERRUPTED, EXCEPTION
    }

}
