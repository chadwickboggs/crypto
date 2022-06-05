package com.tiffanytimbric.crypto;

import org.jetbrains.annotations.NotNull;

import java.io.IOException;


public interface Cryptosystem {

    int getChunkSizeEncrypt();

    void setChunkSizeEncrypt( int chunkSizeEncrypt );

    int getChunkSizeDecrypt();

    void setChunkSizeDecrypt( int chunkSizeDecrypt );

    @NotNull
    byte[] encrypt( @NotNull final byte[] message ) throws IOException;

    @NotNull
    byte[] decrypt( @NotNull final byte[] message ) throws IOException;

}
