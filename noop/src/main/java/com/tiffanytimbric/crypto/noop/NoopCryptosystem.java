package com.tiffanytimbric.crypto.noop;

import com.tiffanytimbric.crypto.api.CryptosystemBase;

import javax.annotation.Nonnull;


/**
 * This class implements NOOP encryption/decryption.
 */
public final class NoopCryptosystem extends CryptosystemBase {

    public static final String NAME = "NOOP";
    public static final int DEFAULT_CHUNK_SIZE_ENCRYPT = 65536;
    public static final int DEFAULT_CHUNK_SIZE_DECRYPT = 65536;

    public NoopCryptosystem() {
        super( DEFAULT_CHUNK_SIZE_ENCRYPT, DEFAULT_CHUNK_SIZE_DECRYPT );
    }

    @Override
    public void init( boolean isBaseNEncode, boolean isBaseNDecode, int baseN ) {
        // Do nothing.
    }

    @Override
    public String getName() {
        return NAME;
    }

    @Nonnull
    public byte[] encrypt( @Nonnull final byte[] message ) {
        return message;
    }

    @Nonnull
    public byte[] decrypt( @Nonnull final byte[] bytes ) {
        return bytes;
    }

}
