package com.tagfoster.crypto.nooputil;

import org.jetbrains.annotations.NotNull;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;


/**
 * This class implements command-line access to NoopUtil encryption/decryption.
 */
public final class Main {

    public static void main( @NotNull final String... args ) throws Exception {
        final List<String> extendedArgs = new ArrayList<>( Arrays.asList( args ) );
        extendedArgs.add( "-c" );
        extendedArgs.add( "NOOP" );

        com.tagfoster.crypto.Main.main( extendedArgs.toArray( new String[]{} ) );
    }

}
