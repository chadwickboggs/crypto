package com.tagfoster.crypto.ntrutil;

import com.tagfoster.crypto.Cryptosystem;
import net.sf.ntru.encrypt.EncryptionKeyPair;
import net.sf.ntru.encrypt.EncryptionParameters;
import net.sf.ntru.encrypt.EncryptionPrivateKey;
import net.sf.ntru.encrypt.EncryptionPublicKey;
import net.sf.ntru.encrypt.NtruEncrypt;
import org.jetbrains.annotations.NotNull;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.IntStream;


/**
 * This class implements NTRU encryption/decryption.  It store its NTRU
 * encryption parameters and keys in the "~/.ntrutil" folder.
 */
public final class NtrUtil implements Cryptosystem {

    private static final String USER_STORE_FOLDER = System.getenv( "HOME" ) + "/.ntrutil";
    private static final String PRIVATE_KEY_FILENAME = USER_STORE_FOLDER + "/encryption_private_key";
    private static final String PUBLIC_KEY_FILENAME = USER_STORE_FOLDER + "/encryption_public_key";
    private static final String ENCRYPTION_PARAMETERS_FILENAME = USER_STORE_FOLDER + "/encryption_parameters";

    private volatile NtruEncrypt ntru = null;
    private volatile EncryptionParameters encryptionParameters = null;
    private volatile EncryptionKeyPair keyPair = null;
    private volatile BufferedReader bufferedReader;
    private int maxMessageLength = 64;


    @NotNull
    public byte[] encrypt( @NotNull final byte[] message ) throws IOException {
        return getNTRU().encrypt( message, getKeyPair().getPublic() );
    }

    @NotNull
    public byte[] decrypt( @NotNull final byte[] message ) throws IOException {
        return getNTRU().decrypt( message, getKeyPair() );
    }


    @NotNull
    public List<byte[]> inputBinary( int intCount, @NotNull final InputStream inputStream ) {
        final List<byte[]> cypherTexts = new ArrayList<>();
        IntStream.rangeClosed( 0, intCount ).forEachOrdered( value -> {
            byte[] input = inputBinary( inputStream );
            if ( input.length > 0 ) {
                cypherTexts.add( input );
            }
        } );

        return cypherTexts;
    }


    @NotNull
    public byte[] inputBinary( @NotNull final InputStream inputStream ) {
        try ( final ByteArrayOutputStream outputStream = new ByteArrayOutputStream() ) {
            byte[] value = new byte[maxMessageLength];
            int numRead;
            while ( (numRead = inputStream.read( value )) == 0 ) ;
            if ( numRead < 0 ) {
                return outputStream.toByteArray();
            }

            outputStream.write( value, 0, numRead );
            outputStream.flush();

            return outputStream.toByteArray();
        }
        catch ( IOException e ) {
            throw new RuntimeException( e );
        }
    }


    @NotNull
    public List<String> inputText( int count, @NotNull final InputStream inputStream ) {
        final List<String> cypherTexts = new ArrayList<>();
        String cypherText;
        do {
            if ( cypherTexts.size() == count ) {
                break;
            }

            cypherText = inputText( inputStream );
            if ( cypherText.length() > 0 ) {
                cypherTexts.add( cypherText );
            }
        }
        while ( cypherText.length() > 0 );

        return cypherTexts;
    }

    @NotNull
    public String inputText( @NotNull final InputStream inputStream ) {
        final StringBuilder buf = new StringBuilder();
        try {
            String line;
            while ( true ) {
                if ( (line = getBufferedReader( inputStream ).readLine()) == null ) break;
                buf.append( line );
                if ( line.endsWith( "==" ) ) break;
            }
        }
        catch ( IOException e ) {
            throw new RuntimeException( e );
        }

        return buf.toString();
    }

    @NotNull
    private synchronized BufferedReader getBufferedReader( @NotNull final InputStream inputStream ) {
        if ( bufferedReader == null ) {
            bufferedReader = new BufferedReader( new InputStreamReader( inputStream ) );
        }

        return bufferedReader;
    }


    @NotNull
    private synchronized NtruEncrypt getNTRU() throws IOException {
        if ( ntru == null ) {
            loadNTRU();
        }

        return ntru;
    }

    @NotNull
    private synchronized EncryptionKeyPair getKeyPair() throws IOException {
        if ( keyPair == null ) {
            loadKeyPair();
        }

        return keyPair;
    }

    @NotNull
    private synchronized EncryptionParameters getEncryptionParameters() throws IOException {
        if ( encryptionParameters == null ) {
            loadEncryptionParameters();
        }

        return encryptionParameters;
    }

    private synchronized void loadEncryptionParameters() throws IOException {
        final File file = new File( ENCRYPTION_PARAMETERS_FILENAME );
        if ( file.isFile() && file.canRead() ) {
            try ( final FileInputStream inputStream = new FileInputStream( file ) ) {
                encryptionParameters = new EncryptionParameters( inputStream );
            }
        }
        else {
            encryptionParameters = EncryptionParameters.APR2011_439_FAST;

            new File( USER_STORE_FOLDER ).mkdirs();

            try ( final FileOutputStream outputStream = new FileOutputStream( ENCRYPTION_PARAMETERS_FILENAME ) ) {
                encryptionParameters.writeTo( outputStream );
            }
        }

        maxMessageLength = encryptionParameters.getMaxMessageLength();
    }

    private synchronized void loadNTRU() throws IOException {
        ntru = new NtruEncrypt( getEncryptionParameters() );
    }

    private synchronized void loadKeyPair() throws IOException {
        File privateKeyFile = new File( PRIVATE_KEY_FILENAME );
        File publicKeyFile = new File( PUBLIC_KEY_FILENAME );

        if ( privateKeyFile.isFile() && privateKeyFile.canRead()
            && publicKeyFile.isFile() && publicKeyFile.canRead() ) {
            keyPair = new EncryptionKeyPair(
                loadEncryptionPrivateKey( privateKeyFile ),
                loadEncryptionPublicKey( publicKeyFile )
            );
        }
        else {
            keyPair = getNTRU().generateKeyPair();

            new File( USER_STORE_FOLDER ).mkdirs();

            try ( final FileOutputStream privKeyOutputStream = new FileOutputStream( PRIVATE_KEY_FILENAME ) ) {
                keyPair.getPrivate().writeTo( privKeyOutputStream );
                privKeyOutputStream.flush();
            }
            try ( final FileOutputStream pubKeyOutputStream = new FileOutputStream( PUBLIC_KEY_FILENAME ) ) {
                keyPair.getPublic().writeTo( pubKeyOutputStream );
                pubKeyOutputStream.flush();
            }
        }
    }

    @NotNull
    private EncryptionPublicKey loadEncryptionPublicKey(
        @NotNull final File publicKeyFile
    ) throws IOException {
        try ( final FileInputStream pubKeyInputStream = new FileInputStream( publicKeyFile ) ) {
            return new EncryptionPublicKey( pubKeyInputStream );
        }
    }

    @NotNull
    private EncryptionPrivateKey loadEncryptionPrivateKey(
        @NotNull final File privateKeyFile
    ) throws IOException {
        try ( final FileInputStream privKeyInputStream = new FileInputStream( privateKeyFile ) ) {
            return new EncryptionPrivateKey( privKeyInputStream );
        }
    }
}
