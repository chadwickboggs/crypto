package com.tagfoster.crypto;

import org.jetbrains.annotations.NotNull;

import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;


public final class Base64Util {

    @NotNull
    public static List<byte[]> decodeBase64( @NotNull final List<String> texts ) {
        return texts.stream().map( Base64Util::decodeBase64 ).collect( Collectors.toList() );
    }

    @NotNull
    public static byte[] decodeBase64( @NotNull final String text ) {
        return Base64.getDecoder().decode( text );
    }

    public static String encodeBase64( @NotNull final byte[] text ) {
        return new String( Base64.getEncoder().encode( text ) );
    }
}
