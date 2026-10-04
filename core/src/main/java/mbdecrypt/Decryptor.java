package mbdecrypt;

import java.security.GeneralSecurityException;

@FunctionalInterface
interface Decryptor {
    byte[] decrypt(byte[] ciphertext) throws GeneralSecurityException;
}
