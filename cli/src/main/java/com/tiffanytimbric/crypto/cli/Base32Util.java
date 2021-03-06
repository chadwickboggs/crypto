package com.tiffanytimbric.crypto.cli;

import org.apache.commons.codec.binary.Base32;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.stream.Collectors;
import javax.annotation.Nonnull;


public final class Base32Util {

    public static final String DELIMITER = "=";

    private static Base32 base32 = new Base32();

    @Nonnull
    public static List<byte[]> decode( @Nonnull final List<String> texts ) {
        return texts.stream().map( Base32Util::decode ).collect( Collectors.toList() );
    }

    @Nonnull
    public static byte[] decode( @Nonnull final String text ) {
        return base32.decode( text );
    }

    @Nonnull
    public static List<String> encode( @Nonnull final List<byte[]> bytes ) {
        return bytes.stream().map( Base32Util::encode ).collect( Collectors.toList() );
    }

    @Nonnull
    public static String encode( @Nonnull final byte[] bytes ) {
        return new String( base32.encode( bytes ), StandardCharsets.UTF_8 );
    }
}
