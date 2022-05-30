package com.tiffanytimbric.crypto.nooputil;

import com.tiffanytimbric.crypto.Cryptosystem;
import org.jetbrains.annotations.NotNull;


/**
 * This class implements NOOP encryption/decryption.
 */
public final class NoopUtil implements Cryptosystem {

    private static final String USER_STORE_FOLDER = System.getenv( "HOME" ) + "/.nooputil";


    @NotNull
    public byte[] encrypt( @NotNull final byte[] message ) {
        return message;
    }

    @NotNull
    public byte[] decrypt( @NotNull final byte[] bytes ) {
        return bytes;
    }

}
