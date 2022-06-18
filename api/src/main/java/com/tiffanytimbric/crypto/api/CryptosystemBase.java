package com.tiffanytimbric.crypto.api;


import com.tiffanytimbric.crypto.api.Cryptosystem;


public abstract class CryptosystemBase implements Cryptosystem {

    protected int chunkSizeEncrypt;
    protected int chunkSizeDecrypt;

    public CryptosystemBase( int chunkSizeEncrypt, int chunkSizeDecrypt ) {
        this.chunkSizeEncrypt = chunkSizeEncrypt;
        this.chunkSizeDecrypt = chunkSizeDecrypt;
    }

    @Override
    public void init( boolean isBaseNEncode, boolean isBaseNDecode, int baseN ) {
        // Do nothing.
    }

    @Override
    public int getChunkSizeEncrypt() {
        return chunkSizeEncrypt;
    }

    @Override
    public void setChunkSizeEncrypt( int chunkSizeEncrypt ) {
        this.chunkSizeEncrypt = chunkSizeEncrypt;
    }

    @Override
    public int getChunkSizeDecrypt() {
        return chunkSizeDecrypt;
    }

    @Override
    public void setChunkSizeDecrypt( int chunkSizeDecrypt ) {
        this.chunkSizeDecrypt = chunkSizeDecrypt;
    }

    @Override
    public boolean isUseChunkSize() {
        return false;
    }
}
