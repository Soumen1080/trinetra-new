package positive;

import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import javax.crypto.Cipher;

/** Positive fixture for the JCA detectors. */
public class CryptoUsage {

    /** Expect AES-CBC with PKCS5 padding, from the transformation string. */
    public Cipher aesCbc() throws Exception {
        return Cipher.getInstance("AES/CBC/PKCS5Padding");
    }

    /** Expect AES-GCM. */
    public Cipher aesGcm() throws Exception {
        return Cipher.getInstance("AES/GCM/NoPadding");
    }

    /** Expect AES-ECB — a finding in its own right regardless of key size. */
    public Cipher aesEcb() throws Exception {
        return Cipher.getInstance("AES/ECB/PKCS5Padding");
    }

    /** Expect MD5. */
    public MessageDigest legacyDigest() throws Exception {
        return MessageDigest.getInstance("MD5");
    }

    /** Expect RSA key generation, with the size carried by initialize(). */
    public KeyPairGenerator rsaKeys() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator;
    }
}
