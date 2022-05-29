package com.tagfoster.crypto.ntrutil;

import com.tagfoster.crypto.Cryptosystem;
import net.sf.ntru.encrypt.EncryptionKeyPair;
import net.sf.ntru.encrypt.EncryptionParameters;
import net.sf.ntru.encrypt.EncryptionPrivateKey;
import net.sf.ntru.encrypt.EncryptionPublicKey;
import net.sf.ntru.encrypt.NtruEncrypt;
import org.jetbrains.annotations.NotNull;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;


/**
 * This class implements NTRU encryption/decryption.  It store its NTRU
 * encryption parameters and keys in the "~/.ntrutil" folder.
 */
public final class NtrUtil implements Cryptosystem {

    private static final String USER_STORE_FOLDER = System.getenv( "HOME" ) + "/.ntrutil";
    private static final String PRIVATE_KEY_FILENAME = USER_STORE_FOLDER + "/encryption_private_key";
    private static final String PUBLIC_KEY_FILENAME = USER_STORE_FOLDER + "/encryption_public_key";
    private static final String ENCRYPTION_PARAMETERS_FILENAME = USER_STORE_FOLDER + "/encryption_parameters";
    private final int messageLength;
    private volatile NtruEncrypt ntru = null;
    private volatile EncryptionParameters encryptionParameters = null;
    private volatile EncryptionKeyPair keyPair = null;

    public NtrUtil( int messageLength ) {
        this.messageLength = messageLength;
    }


    @NotNull
    public byte[] encrypt( @NotNull final byte[] message ) throws IOException {
        return getNTRU().encrypt( message, getKeyPair().getPublic() );
    }

    @NotNull
    public byte[] decrypt( @NotNull final byte[] bytes ) throws IOException {
        return getNTRU().decrypt( bytes, getKeyPair() );
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

        if ( messageLength > encryptionParameters.getMaxMessageLength() ) {
            throw new RuntimeException( String.format(
                "Unsupported message length.  Message Length: %d, Supported Max Message Length: %d",
                messageLength, encryptionParameters.getMaxMessageLength()
            ) );
        }
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
