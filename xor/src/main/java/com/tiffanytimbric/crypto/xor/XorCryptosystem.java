package com.tiffanytimbric.crypto.xor;

import com.tiffanytimbric.crypto.api.CryptosystemBase;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;


/**
 * This class implements XOR encryption/decryption.  It store its XOR
 * encryption parameters and keys in the "~/.xorutil" folder.
 */
public final class XorCryptosystem extends CryptosystemBase {

    public static final int DEFAULT_CHUNK_SIZE_ENCRYPT = 65536;

    public static final int DEFAULT_CHUNK_SIZE_DECRYPT = 65536;

    private static final String USER_STORE_FOLDER = System.getenv( "HOME" ) + "/.xorutil";
    private static final String KEY_FILENAME = USER_STORE_FOLDER + "/encryption_key";
    private volatile byte[] key = null;


    public XorCryptosystem() {
        super( DEFAULT_CHUNK_SIZE_ENCRYPT, DEFAULT_CHUNK_SIZE_DECRYPT );
    }

    private static void validateMessageLength(
        @Nonnull byte[] message, @Nonnull byte[] key
    ) {
        if ( message.length > key.length ) {
            throw new RuntimeException( String.format(
                "Unsupported message length.  Message Length: %d, Supported Max Message Length: %d",
                message.length, key.length
            ) );
        }
    }

    @Override
    public void init( boolean isBaseNEncode, boolean isBaseNDecode, int baseN ) {
        // Do nothing;
    }

    @Nonnull
    public byte[] encrypt( @Nonnull final byte[] message ) throws IOException {
        return xorMessage( message, getKey( getChunkSizeEncrypt() ) );
    }

    @Nonnull
    public byte[] decrypt( @Nonnull final byte[] bytes ) throws IOException {
        return xorMessage( bytes, getKey( getChunkSizeDecrypt() ) );
    }

    @Nonnull
    private byte[] xorMessage( @Nonnull byte[] message, @Nonnull byte[] key ) {
        validateMessageLength( message, key );

        final byte[] xorMessage = new byte[message.length];
        for ( int i = 0; i < message.length; i++ ) {
            xorMessage[i] = (byte) (message[i] ^ key[i]);
        }

        return xorMessage;
    }

    @Nonnull
    private synchronized byte[] getKey( int chunkSize ) throws IOException {
        if ( key == null ) {
            key = readKey( chunkSize );
            if ( key == null ) {
                key = generateKey( chunkSize );
                saveKey( chunkSize );
            }
        }

        return key;
    }

    @Nullable
    private byte[] readKey( int keySize ) throws IOException {
        new File( USER_STORE_FOLDER ).mkdirs();
        if ( !new File( getKeyFilename( keySize ) ).exists() ) {
            return null;
        }

        return Files.readAllBytes( Paths.get( getKeyFilename( keySize ) ) );
    }

    private void saveKey( int keySize ) throws IOException {
        new File( USER_STORE_FOLDER ).mkdirs();
        Files.write( Paths.get( getKeyFilename( keySize ) ), getKey( keySize ) );
    }

    @Nonnull
    private String getKeyFilename( int keySize ) {
        return String.format( "%s.%d", KEY_FILENAME, keySize );
    }

    @Nonnull
    private byte[] generateKey( int keySize ) {
        final byte[] bytes = new byte[keySize];
        final SecureRandom secureRandom = new SecureRandom();
        for ( int i = 0; i < bytes.length; i++ ) {
            bytes[i] = (byte) secureRandom.nextInt();
        }

        return bytes;
    }

}
