package com.tagfoster.crypto.ntrutil;

import org.jetbrains.annotations.NotNull;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;


/**
 * This class implements command-line access to NtrUtil encryption/decryption.
 * Input gets read from stdin.  Output gets written to stdout.  Encryption
 * output is Base64 encoded.  Decryption input is assumed to be Base64 encoded.
 */
public final class Main {

    public static void main( @NotNull final String... args ) throws Exception {
        final List<String> extendedArgs = new ArrayList<>( Arrays.asList( args ) );
        extendedArgs.add( "-c" );
        extendedArgs.add( "NTRU" );

        com.tagfoster.crypto.Main.main( extendedArgs.toArray( new String[]{} ) );
    }

}
