package com.tiffanytimbric.crypto;

public record Config(
    Main.Action action,
    Cryptosystem cryptosystem,
    int chunkSize,
    int threadCount,
    boolean base64DecodeInput,
    boolean base64EncodeOutput,
    boolean useRxJava
) {

}
