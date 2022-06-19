package com.tiffanytimbric.crypto.cli;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;
import javax.annotation.Nonnull;


public final class Base64Util {

    public static final String DELIMITER = "==";

    @Nonnull
    public static List<byte[]> decode( @Nonnull final List<String> texts ) {
        return texts.stream().map( Base64Util::decode ).collect( Collectors.toList() );
    }

    @Nonnull
    public static byte[] decode( @Nonnull final String text ) {
        return Base64.getDecoder().decode( text );
    }

    @Nonnull
    public static List<String> encode( @Nonnull final List<byte[]> bytes ) {
        return bytes.stream().map( Base64Util::encode ).collect( Collectors.toList() );
    }

    @Nonnull
    public static String encode( @Nonnull final byte[] bytes ) {
        return new String( Base64.getEncoder().encode( bytes ), StandardCharsets.UTF_8 );
    }
}
