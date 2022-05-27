package com.tagfoster.crypto;

import com.tagfoster.crypto.ntrutil.NtrUtil;
import com.tagfoster.crypto.xorutil.XorUtil;
import io.reactivex.rxjava3.annotations.NonNull;
import io.reactivex.rxjava3.core.Scheduler;
import io.reactivex.rxjava3.core.Single;
import io.reactivex.rxjava3.internal.schedulers.ExecutorScheduler;
import joptsimple.OptionParser;
import joptsimple.OptionSet;
import org.jetbrains.annotations.NotNull;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.IntStream;

import static com.tagfoster.crypto.Base64Util.decodeBase64;


/**
 * This class implements command-line access to encryption/decryption.  The
 * cryptosystem it should used must be specified as a command line parameter.
 * <br>
 * Presently Supported Cryptosystems: XOR, NTRU
 * <br>
 * Input gets read from stdin.  Output gets written to stdout.  Encryption
 * output is Base64 encoded.  Decryption input is assumed to be Base64 encoded.
 */
public final class Main {

    private static final String USAGE_TXT_FILENAME = "usage-cryptosystem.txt";
    private static final int DEFAULT_THREAD_COUNT = 2;
    private static final int messageLength = 64;
    private static int threadCount = DEFAULT_THREAD_COUNT;
    private volatile static BufferedReader bufferedReader;

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

            if ( !options.has( "c" ) && !options.has( "cryptosystem" ) ) {
                exit( ExitCode.MISSING_CLI_ARGUMENTS.ordinal() );
            }
            final Cryptosystem cryptosystem = getCryptosystem(
                String.valueOf( options.valueOf( "c" ) ), messageLength
            );

            if ( options.has( "t" ) || options.has( "threads" ) ) {
                threadCount = Integer.parseInt( options.valueOf( "t" ).toString() );
            }

            boolean didRead = false;

            while ( true ) {
                //
                // 1. Input one threadCount sized list of chunks.
                //
                final List<byte[]> inputList = readInput( threadCount, options );

                didRead = validateInput( inputList, didRead );

                //
                // 2. Process (encrypt/decrypt) the chunks.
                //
                final byte[][] outputs = processChunks( inputList, cryptosystem, options );

                //
                // 3. Output the processed chunks.
                //
                writeOutput( outputs, options );
            }
        }
        catch ( final Throwable t ) {
            exit( t );
        }

        exit( ExitCode.SUCCESS.ordinal() );
    }

    @NotNull
    public static String usageMessage() throws Exception {
        try ( final InputStream inputStream = NtrUtil.class.getClassLoader().getResourceAsStream( USAGE_TXT_FILENAME ) ) {
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
    private static List<byte[]> inputBinary(
        int intCount, @NotNull final InputStream inputStream
    ) {
        final List<byte[]> cypherTexts = new ArrayList<>();
        IntStream.rangeClosed( 0, intCount ).forEachOrdered( value -> {
            byte[] input = inputBinary( inputStream );
            if ( input.length > 0 ) {
                cypherTexts.add( input );
            }
        } );

        return cypherTexts;
    }


    @NotNull
    private static byte[] inputBinary( @NotNull final InputStream inputStream ) {
        try ( final ByteArrayOutputStream outputStream = new ByteArrayOutputStream() ) {
            byte[] value = new byte[messageLength];
            int numRead;
            while ( (numRead = inputStream.read( value )) == 0 ) ;
            if ( numRead < 0 ) {
                return outputStream.toByteArray();
            }

            outputStream.write( value, 0, numRead );
            outputStream.flush();

            return outputStream.toByteArray();
        }
        catch ( IOException e ) {
            throw new RuntimeException( e );
        }
    }


    @NotNull
    private static List<String> inputText(
        int count, @NotNull final InputStream inputStream
    ) {
        final List<String> cypherTexts = new ArrayList<>();
        String cypherText;
        do {
            if ( cypherTexts.size() == count ) {
                break;
            }

            cypherText = inputText( inputStream );
            if ( cypherText.length() > 0 ) {
                cypherTexts.add( cypherText );
            }
        }
        while ( cypherText.length() > 0 );

        return cypherTexts;
    }

    @NotNull
    private static String inputText( @NotNull final InputStream inputStream ) {
        final StringBuilder buf = new StringBuilder();
        try {
            String line;
            while ( true ) {
                if ( (line = getBufferedReader( inputStream ).readLine()) == null ) break;
                buf.append( line );
                if ( line.endsWith( "==" ) ) break;
            }
        }
        catch ( IOException e ) {
            throw new RuntimeException( e );
        }

        return buf.toString();
    }

    @NotNull
    private synchronized static BufferedReader getBufferedReader( @NotNull final InputStream inputStream ) {
        if ( bufferedReader == null ) {
            bufferedReader = new BufferedReader( new InputStreamReader( inputStream ) );
        }

        return bufferedReader;
    }

    @NotNull
    private static Cryptosystem getCryptosystem(
        @NotNull final String cryptosystemName, int messageLength
    ) {
        Cryptosystem cryptosystem = null;
        switch ( CryptosystemName.valueOf( cryptosystemName ) ) {
            case XOR -> cryptosystem = new XorUtil( messageLength );
            case NTRU -> cryptosystem = new NtrUtil( messageLength );
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

    private static List<byte[]> readInput(
        int chunkCount, @NotNull final OptionSet options
    ) {
        if ( options.has( "e" ) || options.has( "encrypt" ) ) {
            return inputBinary( chunkCount, System.in );
        }

        return decodeBase64( inputText( chunkCount, System.in ) );
    }

    private static void writeOutput(
        @NotNull final byte[][] outputs, @NotNull final OptionSet options
    ) {
        if ( options.has( "e" ) || options.has( "encrypt" ) ) {
            Arrays.stream( outputs ).toList().stream()
                .map( Base64Util::encodeBase64 )
                .forEachOrdered( System.out::println );
        }
        else {
            Arrays.stream( outputs ).toList().stream()
                .map( String::new )
                .forEachOrdered( System.out::print );
        }
    }

    @NotNull
    private static byte[][] processChunks(
        @NotNull final List<byte[]> inputList,
        @NotNull final Cryptosystem cryptosystem,
        @NotNull final OptionSet options
    ) throws InterruptedException {
        if ( options.has( "x" ) || options.has( "rxjava" ) ) {
            return processChunksConcurrentlyUsingRxJava( inputList, cryptosystem, options );
        }

        return processChunksConcurrently( inputList, cryptosystem, options );
    }

    @NotNull
    private static byte[][] processChunksConcurrently(
        @NonNull final List<byte[]> inputList,
        @NonNull final Cryptosystem cryptosystem,
        @NonNull final OptionSet options
    ) throws InterruptedException {
        final byte[][] outputs = new byte[inputList.size()][];

        try ( final ExecutorService executorService = Executors.newFixedThreadPool( threadCount ) ) {
            for ( int i = 0; i < inputList.size(); i++ ) {
                final List<byte[]> inputs = new ArrayList<>( inputList );
                final int index = i;

                if ( options.has( "e" ) || options.has( "encrypt" ) ) {
                    executorService.submit( () ->
                        outputs[index] = cryptosystem.encrypt( inputs.get( index ) )
                    );
                }
                else if ( options.has( "d" ) || options.has( "decrypt" ) ) {
                    executorService.submit( () ->
                        outputs[index] = cryptosystem.decrypt( inputs.get( index ) )
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
    private static byte[][] processChunksConcurrentlyUsingRxJava(
        @NonNull final List<byte[]> inputList,
        @NonNull final Cryptosystem cryptosystem,
        @NonNull final OptionSet options
    ) throws InterruptedException {
        final byte[][] outputs = new byte[inputList.size()][];

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
                            outputs[index] = cryptosystem.encrypt( inputs.get( index ) );
                        }
                        catch ( IOException e ) {
                            exit( e );
                        }
                    } );
                }
                else if ( options.has( "d" ) || options.has( "decrypt" ) ) {
                    executorScheduler.scheduleDirect( () -> {
                        try {
                            outputs[index] = cryptosystem.decrypt( inputs.get( index ) );
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
        final OptionParser parser = new OptionParser( "+c:?e?d?t:?x?h?u?" );

        parser.recognizeAlternativeLongOptions( true );
        parser.accepts( "cryptosystem" );
        parser.accepts( "encrypt" );
        parser.accepts( "decrypt" );
        parser.accepts( "rxjava" );
        parser.accepts( "threads" ).withRequiredArg().defaultsTo( String.valueOf( DEFAULT_THREAD_COUNT ) );
        parser.accepts( "help" );
        parser.accepts( "usage" );

        return parser;
    }


    public enum CryptosystemName {
        XOR, NTRU
    }


    public enum ExitCode {
        SUCCESS, MISSING_CLI_ARGUMENTS, UNRECOGNIZED_ARGUMENT_VALUE, MISSING_RESOURCE, EMPTY_INPUT,
        INTERRUPTED, EXCEPTION
    }

}