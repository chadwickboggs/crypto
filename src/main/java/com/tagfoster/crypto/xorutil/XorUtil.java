package com.tagfoster.crypto.xorutil;

import com.tagfoster.crypto.Cryptosystem;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;


/**
 * This class implements XOR encryption/decryption.  It store its XOR
 * encryption parameters and keys in the "~/.xorutil" folder.
 */
public final class XorUtil implements Cryptosystem {

    private static final String USER_STORE_FOLDER = System.getenv( "HOME" ) + "/.xorutil";
    private static final String KEY_FILENAME = USER_STORE_FOLDER + "/encryption_key";
    private final int keySize;

    private volatile byte[] key = null;


    public XorUtil( int keySize ) {
        this.keySize = keySize;
    }

    private static void validateMessageLength(
        @NotNull byte[] message, @NotNull byte[] key
    ) {
        if ( message.length > key.length ) {
            throw new RuntimeException( String.format(
                "Unsupported message length.  Message Length: %d, Supported Max Message Length: %d",
                message.length, key.length
            ) );
        }
    }

    @NotNull
    public byte[] encrypt( @NotNull final byte[] message ) throws IOException {
        return xorMessage( message, getKey() );
    }

    @NotNull
    public byte[] decrypt( @NotNull final byte[] bytes ) throws IOException {
        return xorMessage( bytes, getKey() );
    }

    @NotNull
    private byte[] xorMessage( @NotNull byte[] message, @NotNull byte[] key ) {
        validateMessageLength( message, key );

        final byte[] messageEncrypted = new byte[message.length];
        for ( int i = 0; i < message.length; i++ ) {
            messageEncrypted[i] = (byte) (message[i] ^ key[i]);
        }

        return messageEncrypted;
    }

    @NotNull
    private synchronized byte[] getKey() throws IOException {
        if ( key == null ) {
            key = readKey();
            if ( key == null ) {
                key = generateKey( keySize );
                saveKey();
            }
        }

        return key;
    }

    @Nullable
    private byte[] readKey() throws IOException {
        new File( USER_STORE_FOLDER ).mkdirs();
        if ( !new File( getKeyFilename() ).exists() ) {
            return null;
        }

        return Files.readAllBytes( Paths.get( getKeyFilename() ) );
    }

    private void saveKey() throws IOException {
        new File( USER_STORE_FOLDER ).mkdirs();
        Files.write( Paths.get( getKeyFilename() ), getKey() );
    }

    @NotNull
    private String getKeyFilename() {
        return String.format( "%s.%d", KEY_FILENAME, keySize );
    }

    @NotNull
    private byte[] generateKey( int keySize ) {
        final byte[] bytes = new byte[keySize];
        final SecureRandom secureRandom = new SecureRandom();
        for ( int i = 0; i < bytes.length; i++ ) {
            bytes[i] = (byte) secureRandom.nextInt();
        }

        return bytes;
    }

}
