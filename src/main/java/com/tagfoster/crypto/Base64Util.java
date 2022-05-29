package com.tagfoster.crypto;

import org.jetbrains.annotations.NotNull;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;


public final class Base64Util {

    @NotNull
    public static List<byte[]> decode( @NotNull final List<String> texts ) {
        return texts.stream().map( Base64Util::decode ).collect( Collectors.toList() );
    }

    @NotNull
    public static byte[] decode( @NotNull final String text ) {
        return Base64.getDecoder().decode( text );
    }

    @NotNull
    public static List<String> encode( @NotNull final List<byte[]> bytes ) {
        return bytes.stream().map( Base64Util::encode ).collect( Collectors.toList() );
    }

    @NotNull
    public static String encode( @NotNull final byte[] bytes ) {
        return new String( Base64.getEncoder().encode( bytes ), StandardCharsets.UTF_8 );
    }
}
