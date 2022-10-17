package com.tiffanytimbric.crypto.cli;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import static org.junit.jupiter.api.Assertions.fail;


class MainTest {

    private static void encrypt(
        @Nonnull final String inputFilename, @Nonnull final String cryptosystemName, int baseN,
        @Nonnull final ByteArrayOutputStream byteArrayOutputStream
    ) throws ValidationException {
        final List<String> encryptArgs = new ArrayList<>( Arrays.asList(
            "-c", cryptosystemName, "-e", "-t", "4"
        ) );
        if ( baseN > 0 ) {
            encryptArgs.add( "-b" );
            encryptArgs.add( String.valueOf( baseN ) );
        }

        new Main(
            Objects.requireNonNull( getInputStreamForResource( inputFilename ) ),
            new PrintStream( byteArrayOutputStream ),
            encryptArgs.toArray( new String[0] )
        ).run();
    }

    private static void decrypt(
        @Nonnull final ByteArrayInputStream inputStream,
        @Nonnull final String cryptosystemName, int baseN,
        @Nonnull final ByteArrayOutputStream byteArrayOutputStreamDecryption
    ) throws ValidationException {
        final List<String> decryptArgs = new ArrayList<>( Arrays.asList(
            "-c", cryptosystemName, "-d", "-t", "4"
        ) );
        if ( baseN > 0 ) {
            decryptArgs.add( "-b" );
            decryptArgs.add( String.valueOf( baseN ) );
        }

        new Main(
            inputStream,
            new PrintStream( byteArrayOutputStreamDecryption ),
            decryptArgs.toArray( new String[0] )
        ).run();
    }

    @Nonnull
    private static String stringFor( @Nonnull final ByteArrayOutputStream byteArrayOutputStream ) {
        return byteArrayOutputStream.toString( StandardCharsets.UTF_8 );
    }

    @Nullable
    private static InputStream getInputStreamForResource( @Nonnull final String filename ) {
        return Main.class.getClassLoader().getResourceAsStream(
            filename
        );
    }

    @ParameterizedTest
    @ValueSource( strings = {"NOOP", "XOR", "NTRU"} )
    void main( @Nonnull final String cryptosystemName ) {
        final List<String> inputFilenames = Arrays.asList(
            "lorem_ipsum_5.txt", "lorem_ipsum_20.txt", "lorem_ipsum_100.txt"
        );
        final List<Integer> baseNs = Arrays.asList( 0, 16, 32, 64 );

        inputFilenames.forEach( inputFilename ->
            baseNs.forEach( baseN ->
                main( inputFilename, cryptosystemName, baseN )
            )
        );
    }

    private void main(
        @Nonnull final String inputFilename, @Nonnull final String cryptosystemName, int baseN
    ) {
        try {
            final ByteArrayOutputStream byteArrayOutputStreamEncryption = new ByteArrayOutputStream();
            encrypt( inputFilename, cryptosystemName, baseN, byteArrayOutputStreamEncryption );

            final ByteArrayOutputStream byteArrayOutputStreamDecryption = new ByteArrayOutputStream();
            decrypt(
                new ByteArrayInputStream( byteArrayOutputStreamEncryption.toByteArray() ),
                cryptosystemName, baseN, byteArrayOutputStreamDecryption
            );

            final String inputString = stringFor( Objects.requireNonNull(
                getInputStreamForResource( inputFilename )
            ) );
            final String decryptedString = stringFor( byteArrayOutputStreamDecryption );

            Assertions.assertEquals( inputString, decryptedString );
        }
        catch ( Throwable t ) {
            fail( t );
        }
    }

    @Nonnull
    private String stringFor( @Nonnull final InputStream inputStream ) throws IOException {
        StringBuilder buf = new StringBuilder();
        final BufferedReader bufferedReader = new BufferedReader( new InputStreamReader( inputStream ) );
        boolean firstLine = true;
        String line;
        while ( (line = bufferedReader.readLine()) != null ) {
            if ( !firstLine ) {
                buf.append( "\n" );
            }
            firstLine = false;

            buf.append( line );
        }

        return buf.toString();
    }
}
