package com.tiffanytimbric.crypto.cli;

import com.tiffanytimbric.crypto.api.Cryptosystem;


public record Config(
    Main.Action action,
    Cryptosystem cryptosystem,
    int chunkSize,
    int threadCount,
    boolean baseNDecodeInput,
    boolean baseNEncodeOutput,
    int baseN,
    boolean useRxJava
) {

}
