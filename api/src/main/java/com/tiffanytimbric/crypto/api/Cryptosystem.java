package com.tiffanytimbric.crypto.api;

import java.io.IOException;
import javax.annotation.Nonnull;


public interface Cryptosystem {

    void init( boolean isBaseNEncode, boolean isBaseNDecode, int baseN );

    int getChunkSizeEncrypt();

    void setChunkSizeEncrypt( int chunkSizeEncrypt );

    int getChunkSizeDecrypt();

    void setChunkSizeDecrypt( int chunkSizeDecrypt );

    @Nonnull
    byte[] encrypt( @Nonnull final byte[] message ) throws IOException;

    @Nonnull
    byte[] decrypt( @Nonnull final byte[] message ) throws IOException;

}
