package com.tiffanytimbric.crypto.ntrutil;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.annotation.Nonnull;


/**
 * This class implements command-line access to NtrUtil encryption/decryption.
 */
public final class Main {

    private static final String USAGE_FILENAME = "usage-ntru.txt";

    public static void main( @Nonnull final String... args ) throws Exception {
        com.tiffanytimbric.crypto.Main.setUsageFilename( USAGE_FILENAME );

        final List<String> extendedArgs = new ArrayList<>( Arrays.asList( args ) );
        extendedArgs.add( "-c" );
        extendedArgs.add( "NTRU" );

        com.tiffanytimbric.crypto.Main.main( extendedArgs.toArray( new String[]{} ) );
    }

}
