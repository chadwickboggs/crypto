package com.tagfoster.crypto.ntrutil;

import org.jetbrains.annotations.NotNull;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;


/**
 * This class implements command-line access to NtrUtil encryption/decryption.
 */
public final class Main {

    private static final String USAGE_FILENAME = "usage-ntru.txt";

    public static void main( @NotNull final String... args ) throws Exception {
        com.tagfoster.crypto.Main.setUsageFilename( USAGE_FILENAME );

        final List<String> extendedArgs = new ArrayList<>( Arrays.asList( args ) );
        extendedArgs.add( "-c" );
        extendedArgs.add( "NTRU" );

        com.tagfoster.crypto.Main.main( extendedArgs.toArray( new String[]{} ) );
    }

}
