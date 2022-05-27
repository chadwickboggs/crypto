package com.tagfoster.crypto;

import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;


public interface Cryptosystem {

    @NotNull
    byte[] encrypt( @NotNull final byte[] message ) throws IOException;

    @NotNull
    byte[] decrypt( @NotNull final byte[] message ) throws IOException;

    @NotNull
    List<byte[]> inputBinary( int intCount, @NotNull final InputStream inputStream );

    @NotNull
    byte[] inputBinary( @NotNull final InputStream inputStream );

    @NotNull
    List<String> inputText( int count, @NotNull final InputStream inputStream );

    @NotNull
    String inputText( @NotNull final InputStream inputStream );

}
