package com.tiffanytimbric.crypto.cli;


import javax.annotation.Nonnull;


public class ValidationException extends Exception {

    static final long serialVersionUID = -3387516993124226948L;

    public ValidationException() {
        super();
    }

    public ValidationException( @Nonnull final String s ) {
        super( s );
    }

    public ValidationException(
        @Nonnull final String message, @Nonnull final Throwable cause
    ) {
        super( message, cause );
    }

    public ValidationException( @Nonnull final Throwable cause ) {
        super( cause );
    }

    protected ValidationException(
        @Nonnull final String message, @Nonnull final Throwable cause,
        boolean enableSuppression, boolean writableStackTrace
    ) {
        super( message, cause, enableSuppression, writableStackTrace );
    }
}
