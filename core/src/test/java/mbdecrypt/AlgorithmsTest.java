package mbdecrypt;

import static mbdecrypt.Fixtures.CARDS_KEY;
import static mbdecrypt.Fixtures.FIXED_IV;
import static mbdecrypt.Fixtures.PII_KEY;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import javax.crypto.AEADBadTagException;
import org.junit.jupiter.api.Test;

class AlgorithmsTest {

    private static Decryptor create(String name, byte[] key) {
        return Algorithms.create(name, key, null, null);
    }

    private static String decrypt(Decryptor decryptor, byte[] value) throws Exception {
        return new String(decryptor.decrypt(value), StandardCharsets.UTF_8);
    }

    @Test
    void aesGcm() throws Exception {
        assertEquals("123-45-6789", decrypt(create("aes-256-gcm", PII_KEY), Fixtures.gcm(PII_KEY, "123-45-6789")));
    }

    @Test
    void aesGcmRejectsTamperedValues() throws Exception {
        byte[] value = Fixtures.gcm(PII_KEY, "123-45-6789");
        value[15] ^= 1;
        assertThrows(AEADBadTagException.class, () -> create("aes-gcm", PII_KEY).decrypt(value));
    }

    @Test
    void namesWorkWithoutDashesInAnyCase() throws Exception {
        assertEquals("123-45-6789", decrypt(create("AES256GCM", PII_KEY), Fixtures.gcm(PII_KEY, "123-45-6789")));
    }

    @Test
    void aesCbc() throws Exception {
        assertEquals("4111111111111111",
                decrypt(create("aes-128-cbc", CARDS_KEY), Fixtures.cbc(CARDS_KEY, "4111111111111111")));
    }

    @Test
    void keysWithAnIvDecryptValuesWithoutOne() throws Exception {
        assertEquals("123-45-6789", decrypt(Algorithms.create("aes-cbc", PII_KEY, FIXED_IV, null),
                Fixtures.cbc(PII_KEY, FIXED_IV, "123-45-6789")));
        assertEquals("123-45-6789", decrypt(Algorithms.create("aes-gcm", PII_KEY, FIXED_IV, null),
                Fixtures.gcm(PII_KEY, FIXED_IV, "123-45-6789")));
    }

    @Test
    void spacePadding() throws Exception {
        Decryptor spaces = Algorithms.create("aes-256-cbc", PII_KEY, null, "spaces");
        for (String name : new String[] {"user", "منفذ النومان", "exactly16bytes!!", ""}) {
            assertEquals(name, decrypt(spaces, Fixtures.spacePadded(PII_KEY, name)));
        }
        assertEquals("user", decrypt(Algorithms.create("aes-cbc", PII_KEY, FIXED_IV, "spaces"),
                Fixtures.cbc(PII_KEY, FIXED_IV, "user      ")));
    }

    @Test
    void zeroPadding() throws Exception {
        Decryptor zeros = Algorithms.create("aes-256-cbc", PII_KEY, null, "zeros");
        for (String name : new String[] {"user", " spaced ", "exactly16bytes!!", ""}) {
            assertEquals(name, decrypt(zeros, Fixtures.cbcPaddedWith((byte) 0, PII_KEY, name)));
        }
    }

    @Test
    void shortValuesFailCleanly() {
        assertThrows(GeneralSecurityException.class, () -> create("aes-gcm", PII_KEY).decrypt(new byte[5]));
        assertThrows(GeneralSecurityException.class, () -> create("aes-cbc", PII_KEY).decrypt(new byte[16]));
        assertThrows(GeneralSecurityException.class,
                () -> Algorithms.create("aes-cbc", PII_KEY, FIXED_IV, null).decrypt(new byte[5]));
    }

    @Test
    void reportsUnsuitableKeysAndUnknownAlgorithms() {
        assertEquals("aes-256-gcm needs a 256-bit key, but this key is 128 bits",
                assertThrows(IllegalArgumentException.class, () -> create("aes-256-gcm", CARDS_KEY)).getMessage());
        assertEquals("AES keys are 128, 192 or 256 bits, but this key is 40 bits",
                assertThrows(IllegalArgumentException.class, () -> create("aes-gcm", new byte[5])).getMessage());
        assertEquals("aes-cbc needs a 16-byte IV, but the IV is 2 bytes",
                assertThrows(IllegalArgumentException.class,
                        () -> Algorithms.create("aes-cbc", PII_KEY, new byte[2], null)).getMessage());
        assertThrows(IllegalArgumentException.class, () -> create("des", PII_KEY));
        assertThrows(IllegalArgumentException.class, () -> create("aes-cbc-zero-iv", PII_KEY));
        assertEquals("padding=\"spaces\" is only for aes-cbc", assertThrows(IllegalArgumentException.class,
                () -> Algorithms.create("aes-gcm", PII_KEY, null, "spaces")).getMessage());
        assertEquals("padding=\"zeros\" is only for aes-cbc", assertThrows(IllegalArgumentException.class,
                () -> Algorithms.create("aes-gcm", PII_KEY, null, "zeros")).getMessage());
        assertEquals("unknown padding 'ansix923'; use pkcs7, spaces or zeros",
                assertThrows(IllegalArgumentException.class,
                        () -> Algorithms.create("aes-cbc", PII_KEY, null, "ansix923")).getMessage());
    }
}
