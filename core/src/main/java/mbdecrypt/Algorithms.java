package mbdecrypt;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Locale;
import java.util.function.UnaryOperator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * The algorithms decryptors can use: {@code aes[-size]-gcm} and
 * {@code aes[-size]-cbc}, case-insensitive, optional dashes.
 */
final class Algorithms {
    private static final Pattern NAME = Pattern.compile("aes(128|192|256)?(gcm|cbc)");

    private Algorithms() {
    }

    /** Create a {@code Decryptor} based on the provided configuration. */
    static Decryptor create(String name, byte[] secret, byte[] iv, String padding) throws IllegalArgumentException {
        Matcher m = NAME.matcher(compact(name));
        if (!m.matches()) {
            throw new IllegalArgumentException(
                    "unknown algorithm '%s'; use aes-gcm or aes-cbc, optionally with the key size, e.g. aes-256-gcm"
                            .formatted(name));
        }

        UnaryOperator<byte[]> unpad = switch (padding) {
            case null -> null; // pkcs7
            case "pkcs7" -> null;
            case "spaces" -> Algorithms::trim;
            case "zeros" -> Algorithms::stripZeros;
            default -> throw new IllegalArgumentException(
                    "unknown padding '%s'; use pkcs7, spaces or zeros".formatted(padding));
        };

        var size = m.group(1);
        var type = m.group(2);
        SecretKey aes = aes(name, size, secret);
        if (type.equals("gcm")) {
            if (unpad != null) {
                throw new IllegalArgumentException("padding=\"%s\" is only for aes-cbc".formatted(padding));
            }
            return iv == null ? gcm(aes) : gcm(aes, iv);
        }

        if (iv != null && iv.length != 16) {
            throw new IllegalArgumentException(
                    "%s needs a 16-byte IV, but the IV is %d bytes".formatted(name, iv.length));
        }
        return iv == null ? cbc(aes, unpad) : cbc(aes, iv, unpad);
    }

    private static String compact(String name) {
        return name.toLowerCase(Locale.ROOT).replace("-", "");
    }

    /** {@code nonce(12) || ciphertext || tag(16)}. */
    private static Decryptor gcm(SecretKey key) {
        return value -> {
            if (value.length < 12 + 16) {
                throw new GeneralSecurityException("value is too short to be AES-GCM ciphertext");
            }
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, value, 0, 12));
            return cipher.doFinal(value, 12, value.length - 12);
        };
    }

    /** {@code ciphertext || tag(16)}, with a fixed nonce. */
    private static Decryptor gcm(SecretKey key, byte[] nonce) {
        return value -> {
            if (value.length < 16) {
                throw new GeneralSecurityException("value is too short to be AES-GCM ciphertext");
            }
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, nonce));
            return cipher.doFinal(value);
        };
    }

    private static Decryptor cbc(SecretKey key, UnaryOperator<byte[]> unpad) {
        return value -> {
            if (value.length < (unpad != null ? 16 : 16 + 16)) {
                throw new GeneralSecurityException("value is too short to be an IV followed by AES-CBC ciphertext");
            }
            Cipher cipher = Cipher.getInstance(unpad != null ? "AES/CBC/NoPadding" : "AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(value, 0, 16));
            byte[] plaintext = cipher.doFinal(value, 16, value.length - 16);
            return unpad != null ? unpad.apply(plaintext) : plaintext;
        };
    }

    private static Decryptor cbc(SecretKey key, byte[] iv, UnaryOperator<byte[]> unpad) {
        return value -> {
            if (unpad == null && value.length < 16) {
                throw new GeneralSecurityException("value is too short to be AES-CBC ciphertext");
            }
            Cipher cipher = Cipher.getInstance(unpad != null ? "AES/CBC/NoPadding" : "AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
            byte[] plaintext = cipher.doFinal(value);
            return unpad != null ? unpad.apply(plaintext) : plaintext;
        };
    }

    private static byte[] trim(byte[] bytes) {
        int start = 0;
        int end = bytes.length;
        while (start < end && (bytes[start] & 0xff) <= ' ') {
            start++;
        }
        while (end > start && (bytes[end - 1] & 0xff) <= ' ') {
            end--;
        }
        return Arrays.copyOfRange(bytes, start, end);
    }

    private static byte[] stripZeros(byte[] bytes) {
        int end = bytes.length;
        while (end > 0 && bytes[end - 1] == 0) {
            end--;
        }
        return Arrays.copyOf(bytes, end);
    }

    private static SecretKey aes(String name, String size, byte[] key) throws IllegalArgumentException {
        int bits = key.length * 8;
        if (bits != 128 && bits != 192 && bits != 256) {
            throw new IllegalArgumentException(
                    "AES keys are 128, 192 or 256 bits, but this key is %d bits".formatted(bits));
        }
        if (size != null && Integer.parseInt(size) != bits) {
            throw new IllegalArgumentException(
                    "%s needs a %s-bit key, but this key is %d bits".formatted(name, size, bits));
        }
        return new SecretKeySpec(key, "AES");
    }
}
