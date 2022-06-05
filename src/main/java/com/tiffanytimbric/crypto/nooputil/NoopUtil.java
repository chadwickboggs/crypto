package com.tiffanytimbric.crypto.nooputil;

import com.tiffanytimbric.crypto.CryptosystemBase;
import org.jetbrains.annotations.NotNull;


/**
 * This class implements NOOP encryption/decryption.
 */
public final class NoopUtil extends CryptosystemBase {

    public static final int DEFAULT_CHUNK_SIZE_ENCRYPT = 65536;
    public static final int DEFAULT_CHUNK_SIZE_DECRYPT = 65536;


    public NoopUtil() {
        super( DEFAULT_CHUNK_SIZE_ENCRYPT, DEFAULT_CHUNK_SIZE_DECRYPT );
    }

    @NotNull
    public byte[] encrypt( @NotNull final byte[] message ) {
        return message;
    }

    @NotNull
    public byte[] decrypt( @NotNull final byte[] bytes ) {
        return bytes;
    }

}
