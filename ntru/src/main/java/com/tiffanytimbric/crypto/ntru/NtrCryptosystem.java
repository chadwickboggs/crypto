package com.tiffanytimbric.crypto.ntru;

import com.tiffanytimbric.crypto.api.CryptosystemBase;
import net.sf.ntru.encrypt.EncryptionKeyPair;
import net.sf.ntru.encrypt.EncryptionParameters;
import net.sf.ntru.encrypt.EncryptionPrivateKey;
import net.sf.ntru.encrypt.EncryptionPublicKey;
import net.sf.ntru.encrypt.NtruEncrypt;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import javax.annotation.Nonnull;


/**
 * This class implements NTRU encryption/decryption.  It store its NTRU
 * encryption parameters and keys in the "~/.ntrutil" folder.
 */
public final class NtrCryptosystem extends CryptosystemBase {

    public static final int DEFAULT_CHUNK_SIZE_ENCRYPT = 64;
    public static final int DEFAULT_CHUNK_SIZE_DECRYPT = 604; // 16:1208, 32:968, 64:808
    public static final int BASE16_CHUNK_SIZE_DECRYPT = 1208;
    public static final int BASE32_CHUNK_SIZE_DECRYPT = 968;
    public static final int BASE64_CHUNK_SIZE_DECRYPT = 808;
    private static final String USER_STORE_FOLDER = System.getenv( "HOME" ) + "/.ntrutil";
    private static final String PRIVATE_KEY_FILENAME = USER_STORE_FOLDER + "/encryption_private_key";
    private static final String PUBLIC_KEY_FILENAME = USER_STORE_FOLDER + "/encryption_public_key";
    private static final String ENCRYPTION_PARAMETERS_FILENAME = USER_STORE_FOLDER + "/encryption_parameters";
    private volatile NtruEncrypt ntru = null;
    private volatile EncryptionParameters encryptionParameters = null;
    private volatile EncryptionKeyPair keyPair = null;


    public NtrCryptosystem() {
        super( DEFAULT_CHUNK_SIZE_ENCRYPT, DEFAULT_CHUNK_SIZE_DECRYPT );
    }


    @Override
    public void init( boolean isBaseNEncode, boolean isBaseNDecode, int baseN ) {
        if ( !isBaseNDecode ) {
            return;
        }

        if ( 16 == baseN ) {
            setChunkSizeDecrypt( BASE16_CHUNK_SIZE_DECRYPT );
        }
        if ( 32 == baseN ) {
            setChunkSizeDecrypt( BASE32_CHUNK_SIZE_DECRYPT );
        }
        if ( 64 == baseN ) {
            setChunkSizeDecrypt( BASE64_CHUNK_SIZE_DECRYPT );
        }
    }

    @Nonnull
    public byte[] encrypt( @Nonnull final byte[] message ) throws IOException {
        return getNTRU().encrypt( message, getKeyPair().getPublic() );
    }

    @Nonnull
    public byte[] decrypt( @Nonnull final byte[] bytes ) throws IOException {
        return getNTRU().decrypt( bytes, getKeyPair() );
    }


    @Nonnull
    private synchronized NtruEncrypt getNTRU() throws IOException {
        if ( ntru == null ) {
            loadNTRU();
        }

        return ntru;
    }

    @Nonnull
    private synchronized EncryptionKeyPair getKeyPair() throws IOException {
        if ( keyPair == null ) {
            loadKeyPair();
        }

        return keyPair;
    }

    @Nonnull
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

        if ( chunkSizeEncrypt > encryptionParameters.getMaxMessageLength() ) {
            throw new RuntimeException( String.format(
                "Unsupported message length.  Message Length: %d, Supported Max Message Length: %d",
                chunkSizeEncrypt, encryptionParameters.getMaxMessageLength()
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

    @Nonnull
    private EncryptionPublicKey loadEncryptionPublicKey(
        @Nonnull final File publicKeyFile
    ) throws IOException {
        try ( final FileInputStream pubKeyInputStream = new FileInputStream( publicKeyFile ) ) {
            return new EncryptionPublicKey( pubKeyInputStream );
        }
    }

    @Nonnull
    private EncryptionPrivateKey loadEncryptionPrivateKey(
        @Nonnull final File privateKeyFile
    ) throws IOException {
        try ( final FileInputStream privKeyInputStream = new FileInputStream( privateKeyFile ) ) {
            return new EncryptionPrivateKey( privKeyInputStream );
        }
    }

    @Override
    public boolean isUseChunkSize() {
        return true;
    }
}
