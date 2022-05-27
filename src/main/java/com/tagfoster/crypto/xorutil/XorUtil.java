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
 * This class implements NTRU encryption/decryption.  It store its NTRU
 * encryption parameters and keys in the "~/.ntrutil" folder.
 */
public final class XorUtil implements Cryptosystem {

    private static final String USER_STORE_FOLDER = System.getenv( "HOME" ) + "/.xorutil";
    private static final String SHARED_KEY_FILENAME = USER_STORE_FOLDER + "/encryption_key";
    private final int messageLength;

    private volatile byte[] sharedKey = null;


    public XorUtil( int messageLength ) {
        this.messageLength = messageLength;
    }

    private static void validateMessageLength(
        @NotNull byte[] message, @NotNull byte[] sharedKey
    ) {
        if ( message.length > sharedKey.length ) {
            throw new RuntimeException( String.format(
                "Unsupported message length.  Message Length: %d, Supported Max Message Length: %d",
                message.length, sharedKey.length
            ) );
        }
    }

    @NotNull
    public byte[] encrypt( @NotNull final byte[] message ) throws IOException {
        return xorMessage( message, getSharedKey() );
    }

    @NotNull
    public byte[] decrypt( @NotNull final byte[] message ) throws IOException {
        return xorMessage( message, getSharedKey() );
    }

    @NotNull
    private byte[] xorMessage( @NotNull byte[] message, @NotNull byte[] sharedKey ) {
        validateMessageLength( message, sharedKey );

        final byte[] messageEncrypted = new byte[message.length];
        for ( int i = 0; i < message.length; i++ ) {
            messageEncrypted[i] = (byte) (message[i] ^ sharedKey[i]);
        }

        return messageEncrypted;
    }

    @NotNull
    private synchronized byte[] getSharedKey() throws IOException {
        if ( sharedKey == null ) {
            sharedKey = readSharedKey();
            if ( sharedKey == null ) {
                sharedKey = generateSharedKey( messageLength );
                saveSharedKey();
            }
        }

        return sharedKey;
    }

    @Nullable
    private byte[] readSharedKey() throws IOException {
        new File( USER_STORE_FOLDER ).mkdirs();
        if ( !new File( SHARED_KEY_FILENAME ).exists() ) {
            return null;
        }

        return Files.readAllBytes( Paths.get( SHARED_KEY_FILENAME ) );
    }

    private void saveSharedKey() throws IOException {
        new File( USER_STORE_FOLDER ).mkdirs();
        Files.write( Paths.get( SHARED_KEY_FILENAME ), getSharedKey() );
    }

    @NotNull
    private byte[] generateSharedKey( int messageLength ) {
        final byte[] bytes = new byte[messageLength];
        final SecureRandom secureRandom = new SecureRandom();
        for ( int i = 0; i < bytes.length; i++ ) {
            bytes[i] = (byte) secureRandom.nextInt();
        }

        return bytes;
    }

}
