package com.tiffanytimbric.crypto.cli;

import org.apache.commons.codec.binary.Base16;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.stream.Collectors;
import javax.annotation.Nonnull;


public final class Base16Util {

    private static Base16 base16 = new Base16();

    @Nonnull
    public static List<byte[]> decode( @Nonnull final List<String> texts ) {
        return texts.stream().map( Base16Util::decode ).collect( Collectors.toList() );
    }

    @Nonnull
    public static byte[] decode( @Nonnull final String text ) {
        return base16.decode( text );
    }

    @Nonnull
    public static List<String> encode( @Nonnull final List<byte[]> bytes ) {
        return bytes.stream().map( Base16Util::encode ).collect( Collectors.toList() );
    }

    @Nonnull
    public static String encode( @Nonnull final byte[] bytes ) {
        return new String( base16.encode( bytes ), StandardCharsets.UTF_8 );
    }
}
