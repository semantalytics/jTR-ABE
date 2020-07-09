package trabe.aes;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import trabe.AbeDecryptionException;
import trabe.AbeEncryptionException;

public class AesEncryption {

    private static final String KEY_ALGORITHM = "AES";
    private static final String CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding"; //"AES/GCM/NoPadding" not working on android
    private static final String HASHING_ALGORITHM = "SHA-256";
    private static final int BUFFERSIZE = 1024;
    // We use AES128 per schneier, so we need to reduce the keysize
    private static final int AES_KEY_LENGTH = 16;
    
    static {
    	//Security.addProvider(new BouncyCastleProvider());
    }

    private AesEncryption() {
        throw new AssertionError("Surpressing constructor for static class");
    }

    private static byte[] hash(byte[] cpabeData) {
        try {
            final MessageDigest sha256 = MessageDigest.getInstance(HASHING_ALGORITHM);
            return Arrays.copyOf(sha256.digest(cpabeData), AES_KEY_LENGTH);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            System.err.println(HASHING_ALGORITHM + " not provided by runtime environment. Exiting...");
            System.exit(1);
        }
        return null;
    }
    
    private static byte[] combine(final byte[] cpabeData, final byte[] lbeKey) {
    	final byte[] hashedCpabeSecret = hash(cpabeData);
    	if (lbeKey != null) {
    		if (hashedCpabeSecret.length != lbeKey.length) {
    			throw new RuntimeException("wrong key size for lbeKey, " + hashedCpabeSecret.length + " bytes required");
    		}
    		for (int i = 0; i < lbeKey.length; i++) {
    			hashedCpabeSecret[i] = (byte) (hashedCpabeSecret[i] ^ lbeKey[i]);
    		}
    	}
    	return hashedCpabeSecret;
    }
	
	public static void encrypt(final byte[] cpabeKey,
                               final byte[] lbeKey,
                               final byte[] iv,
                               final InputStream input,
                               final OutputStream output) throws IOException, AbeEncryptionException {
        try {
            final CipherInputStream cis = encrypt(cpabeKey, lbeKey, iv, input);
            int read;
            final byte[] buffer = new byte[BUFFERSIZE];
            while ((read = cis.read(buffer)) >= 0) {
            	output.write(buffer, 0, read);
            }
            output.close();
            cis.close();
        } catch (GeneralSecurityException e) {
            throw new AbeEncryptionException(e.getMessage(), e);
        }
	}

    public static byte[] encrypt(final byte[] cpabeKey,
                                 final byte[] lbeKey,
                                 final byte[] iv,
                                 final byte[] data) throws IOException, AbeEncryptionException {
        final ByteArrayInputStream bais = new ByteArrayInputStream(data);
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        encrypt(cpabeKey, lbeKey, iv, bais, baos);
        return baos.toByteArray();
    }
	
	public static CipherInputStream encrypt(final byte[] cpabeKey,
                                            final byte[] lbeKey,
                                            final byte[] iv, InputStream input) throws AbeEncryptionException {
        try {
            final SecretKeySpec skeySpec = new SecretKeySpec(combine(cpabeKey, lbeKey), KEY_ALGORITHM);
            final Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, new IvParameterSpec(iv));
            final CipherInputStream cis = new CipherInputStream(input, cipher);
            return cis;
        } catch (GeneralSecurityException e) {
            throw new AbeEncryptionException(e.getMessage(), e);
        }
	}
	
	public static CipherInputStream decrypt(final byte[] cpabeKey,
                                            final byte[] lbeKey,
                                            final byte[] iv,
                                            final InputStream input) throws AbeDecryptionException {
        try {
            final SecretKeySpec skeySpec = new SecretKeySpec(combine(cpabeKey, lbeKey), KEY_ALGORITHM);
            final Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, new IvParameterSpec(iv));
            return new CipherInputStream(input, cipher);
        } catch (GeneralSecurityException e) {
            throw new AbeDecryptionException(e.getMessage(), e);
        }
	}

    public static Cipher decrypt(final byte[] cpabeKey, final byte[] lbeKey, final byte[] iv) {
        try {
            final SecretKeySpec skeySpec = new SecretKeySpec(combine(cpabeKey, lbeKey), KEY_ALGORITHM);
            final Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, new IvParameterSpec(iv));
            return cipher;
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }
	
	public static void decrypt(final byte[] cpabeKey,
                               final byte[] lbeKey,
                               final byte[] iv,
                               final InputStream input,
                               final OutputStream output) throws IOException, AesDecryptionException {
        final Cipher cipher = decrypt(cpabeKey, lbeKey, iv);
        int read;
        final byte[] buffer = new byte[BUFFERSIZE];
        while ((read = input.read(buffer)) >= 0) {
            byte[] dec = cipher.update(buffer, 0, read);
            output.write(dec);
        }
        try {
            final byte[] dec = cipher.doFinal();
            output.write(dec);
        } catch (Exception e) {
            throw new AesDecryptionException(e);
        }
	}

    public static byte[] decrypt(final byte[] cpabeKey,
                                 final byte[] lbeKey,
                                 final byte[] iv,
                                 final byte[] data) throws IOException, AesDecryptionException {
        final ByteArrayInputStream bais = new ByteArrayInputStream(data);
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        decrypt(cpabeKey, lbeKey, iv, bais, baos);
        return baos.toByteArray();
    }
}