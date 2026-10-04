package mbdecrypt;

/**
 * How to decrypt the columns a rule picks.
 *
 * @param pattern    the rule's pattern setting, or {@code decrypt_<name>_*} for a column alias prefix
 * @param decryptor  decrypts the stored values
 * @param showErrors whether to display decryption errors as column values
 */
record Rule(String pattern, Decryptor decryptor, boolean showErrors) {}
