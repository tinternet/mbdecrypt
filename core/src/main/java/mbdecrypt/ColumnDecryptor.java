package mbdecrypt;

import java.lang.System.Logger.Level;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Base64;
import java.util.HexFormat;
import java.util.regex.Pattern;

public final class ColumnDecryptor {
    private static final System.Logger LOG = System.getLogger("mbdecrypt");
    private static final Pattern HEX = Pattern.compile("(0[xX])?(\\p{XDigit}{2})+");
    private static final Pattern WHITESPACE = Pattern.compile("\\s+");

    private final Rule rule;
    private final ColumnDescription column;

    ColumnDecryptor(Rule rule, ColumnDescription column) {
        this.rule = rule;
        this.column = column;
    }

    /** Reads and decrypts the current row's value */
    public String read(ResultSet rs, int index) throws SQLException {
        var stored = column.isBinary() ? rs.getBytes(index) : rs.getString(index);
        if (stored == null) {
            return null;
        }

        try {
            byte[] ciphertext = stored instanceof String text ? decode(text) : (byte[]) stored;
            if (ciphertext.length == 0) {
                return "";
            }
            return StandardCharsets.UTF_8.newDecoder()
                    .decode(ByteBuffer.wrap(rule.decryptor().decrypt(ciphertext)))
                    .toString();
        } catch (GeneralSecurityException | IllegalArgumentException | CharacterCodingException e) {
            LOG.log(Level.DEBUG,
                    "can't decrypt column '%s' (rule for '%s'): %s".formatted(column.label(), rule.pattern(), e));
            if (rule.showErrors()) {
                return "[can't decrypt: %s]".formatted(reason(e));
            }
            return stored instanceof byte[] raw ? "0x" + HexFormat.of().withUpperCase().formatHex(raw)
                    : (String) stored;
        }
    }

    /** Describe why a value couldn't decrypt. */
    private static String reason(Exception e) {
        if (e instanceof IllegalArgumentException) {
            return "the value isn't hex or Base64";
        }
        if (e instanceof CharacterCodingException) {
            return "the result isn't UTF-8 text; the key or algorithm is probably wrong";
        }
        return "wrong key or algorithm, or not encrypted (%s)".formatted(e.getMessage());
    }

    /** Get the bytes of a hex or base64 string */
    private static byte[] decode(String text) {
        String t = text.strip();
        if (HEX.matcher(t).matches()) {
            return HexFormat.of().parseHex(t, t.startsWith("0x") || t.startsWith("0X") ? 2 : 0, t.length());
        }
        return Base64.getDecoder().decode(WHITESPACE.matcher(t).replaceAll(""));
    }
}
