package com.tiffanytimbric.crypto;

import org.jetbrains.annotations.NotNull;


public class ValidationException extends Exception {

    static final long serialVersionUID = -3387516993124226948L;

    public ValidationException() {
        super();
    }

    public ValidationException( @NotNull final String s ) {
        super( s );
    }

    public ValidationException(
        @NotNull final String message, @NotNull final Throwable cause
    ) {
        super( message, cause );
    }

    public ValidationException( @NotNull final Throwable cause ) {
        super( cause );
    }

    protected ValidationException(
        @NotNull final String message, @NotNull final Throwable cause,
        boolean enableSuppression, boolean writableStackTrace
    ) {
        super( message, cause, enableSuppression, writableStackTrace );
    }
}
