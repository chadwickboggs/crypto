package com.tiffanytimbric.crypto;

public class ValidationException extends Exception {

    static final long serialVersionUID = -3387516993124226948L;

    public ValidationException() {
        super();
    }

    public ValidationException( String s ) {
        super( s );
    }

    public ValidationException( String message, Throwable cause ) {
        super( message, cause );
    }

    public ValidationException( Throwable cause ) {
        super( cause );
    }

    protected ValidationException( String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace ) {
        super( message, cause, enableSuppression, writableStackTrace );
    }
}
