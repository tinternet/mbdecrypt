package mbdecrypt;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** Test keys, and the encrypting side of each algorithm. */
public final class Fixtures {
    public static final byte[] PII_KEY =
            HexFormat.of().parseHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    public static final byte[] CARDS_KEY = HexFormat.of().parseHex("f0e0d0c0b0a090807060504030201000");
    public static final byte[] FIXED_IV = HexFormat.of().parseHex("0f0e0d0c0b0a09080706050403020100");
    /** As the decrypt-decryptors setting; "fixed" is AES-CBC with the PII key and FIXED_IV. */
    public static final String DECRYPTORS = """
            <decryptor name="pii" algorithm="aes-256-gcm" key="%1$s"/>
            <decryptor name="cards" algorithm="aes-128-cbc" key="%2$s"/>
            <decryptor name="fixed" algorithm="aes-cbc" key="%1$s" iv="%3$s"/>
            """.formatted(HexFormat.of().formatHex(PII_KEY), HexFormat.of().formatHex(CARDS_KEY),
            HexFormat.of().formatHex(FIXED_IV));

    private static final SecureRandom RANDOM = new SecureRandom();

    private Fixtures() {}

    /** AES-GCM, {@code nonce || ciphertext || tag}. */
    public static byte[] gcm(byte[] key, String plaintext) throws Exception {
        byte[] nonce = random(12);
        return concat(nonce, gcm(key, nonce, plaintext));
    }

    /** AES-GCM with a given nonce, {@code ciphertext || tag}. */
    public static byte[] gcm(byte[] key, byte[] nonce, String plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        return cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
    }

    /** AES-CBC with PKCS#7 padding, {@code iv || ciphertext}. */
    public static byte[] cbc(byte[] key, String plaintext) throws Exception {
        byte[] iv = random(16);
        return concat(iv, cbc(key, iv, plaintext));
    }

    /** AES-CBC with PKCS#7 padding and a given IV, {@code ciphertext}. */
    public static byte[] cbc(byte[] key, byte[] iv, String plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        return cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * AES-CBC with a random first block, which works as the IV, then the plaintext padded with spaces to whole blocks
     * (none if it fills them), without PKCS#7 padding.
     */
    public static byte[] spacePadded(byte[] key, String plaintext) throws Exception {
        return cbcPaddedWith((byte) ' ', key, plaintext);
    }

    /** AES-CBC, {@code iv || ciphertext}, with the plaintext padded with {@code pad} bytes instead of PKCS#7. */
    public static byte[] cbcPaddedWith(byte pad, byte[] key, String plaintext) throws Exception {
        byte[] text = plaintext.getBytes(StandardCharsets.UTF_8);
        byte[] padded = java.util.Arrays.copyOf(text, (text.length + 15) / 16 * 16);
        java.util.Arrays.fill(padded, text.length, padded.length, pad);
        byte[] iv = random(16);
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        return concat(iv, cipher.doFinal(padded));
    }

    public static String base64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    private static byte[] random(int length) {
        byte[] bytes = new byte[length];
        RANDOM.nextBytes(bytes);
        return bytes;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }
}
