package com.tiffanytimbric.crypto.xorutil;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.annotation.Nonnull;


/**
 * This class implements command-line access to XorUtil encryption/decryption.
 */
public final class Main {

    private static final String USAGE_FILENAME = "usage-xor.txt";

    public static void main( @Nonnull final String... args ) throws Exception {
        com.tiffanytimbric.crypto.Main.setUsageFilename( USAGE_FILENAME );

        final List<String> extendedArgs = new ArrayList<>( Arrays.asList( args ) );
        extendedArgs.add( "-c" );
        extendedArgs.add( "XOR" );

        com.tiffanytimbric.crypto.Main.main( extendedArgs.toArray( new String[]{} ) );
    }

}
