package mbdecrypt;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.sql.Types;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.Test;

class RulesTest {

    private static ColumnDescription column(String label, String name, String table, String schema) {
        return new ColumnDescription(label, name, table, schema, Types.VARCHAR);
    }

    @Test
    void parsesXml() {
        assertEquals(List.of(new Rules.Element("dbo.customers.ssn", "pii"), new Rules.Element("/^enc:(.+)$/", "pii")),
                Rules.elements("""
                        <rule pattern="dbo.customers.ssn" decryptor="pii"/>
                        <rule pattern="/^enc:(.+)$/" decryptor="pii"/>
                        """));
    }

    @Test
    void rulesAreOptionalButNeedAllFields() {
        assertEquals(List.of(), Rules.elements(null));
        assertEquals(List.of(), Rules.elements(" "));
        assertParseError("every rule needs a pattern and a decryptor: Element[pattern=ssn, decryptor=null]",
                "<rule pattern=\"ssn\"/>");
    }

    @Test
    void invalidRulesXmlSaysWhere() {
        assertTrue(assertThrows(IllegalArgumentException.class, () -> Rules.elements("<rule pattern=\"a\"/>\n<rule"))
                .getMessage().startsWith("Encrypted columns in the connection settings aren't valid XML (line 2): "));
    }

    private static void assertParseError(String expected, String xml) {
        assertEquals(expected,
                assertThrows(IllegalArgumentException.class, () -> Rules.elements(xml)).getMessage());
    }

    @Test
    void parsesDecryptors() throws Exception {
        Decryptors decryptors = Decryptors.parse(Fixtures.DECRYPTORS);
        assertArrayEquals("hi".getBytes(StandardCharsets.UTF_8),
                decryptors.get("FIXED").decrypt(Fixtures.cbc(Fixtures.PII_KEY, Fixtures.FIXED_IV, "hi")));
        assertEquals("user", new String(Decryptors.parse("<decryptor name=\"spaces\" algorithm=\"aes-256-cbc\" key=\""
                + HexFormat.of().formatHex(Fixtures.PII_KEY) + "\" padding=\"spaces\"/>").get("spaces")
                .decrypt(Fixtures.spacePadded(Fixtures.PII_KEY, "user")), StandardCharsets.UTF_8));
        assertEquals("no decryptor named 'nope'; the decryptors are [pii, cards, fixed]",
                assertThrows(IllegalArgumentException.class, () -> decryptors.get("nope")).getMessage());
    }

    @Test
    void decryptorErrorsDontShowKeys() {
        assertDecryptorsError("no decryptors are configured; add them to the connection settings, under Decryptors, as "
                + "<decryptor name=\"…\" algorithm=\"…\" key=\"<hex>\"/>", " ");
        assertDecryptorsError("Decryptors in the connection settings aren't valid XML (line 2)",
                "<decryptor name=\"a\"/>\n<decryptor key=\"secret");
        assertDecryptorsError("decryptor 1 needs a name of letters and digits", "<decryptor name=\"my_key\"/>");
        assertDecryptorsError("decryptor 'a' needs an algorithm", "<decryptor name=\"a\" key=\"00\"/>");
        String badKey = "decryptor 'a' needs both the key and iv (if any) in hex";
        assertDecryptorsError(badKey, "<decryptor name=\"a\" algorithm=\"aes-gcm\" key=\"0g11223344\"/>");
        assertDecryptorsError(badKey, "<decryptor name=\"a\" algorithm=\"aes-gcm\"/>");
        assertDecryptorsError(badKey, "<decryptor name=\"a\" algorithm=\"aes-gcm\" key=\"00\" iv=\"\"/>");
        String key = HexFormat.of().formatHex(Fixtures.CARDS_KEY);
        assertDecryptorsError("decryptor 'a': aes-256-gcm needs a 256-bit key, but this key is 128 bits",
                "<decryptor name=\"a\" algorithm=\"aes-256-gcm\" key=\"" + key + "\"/>");
        assertDecryptorsError("decryptor 'a': it's configured twice", "<decryptor name=\"a\" algorithm=\"aes-gcm\" key=\""
                + key + "\"/><decryptor name=\"A\" algorithm=\"aes-cbc\" key=\"" + key + "\"/>");
    }

    private static void assertDecryptorsError(String expected, String xml) {
        assertEquals(expected, assertThrows(IllegalArgumentException.class, () -> Decryptors.parse(xml)).getMessage());
    }

    @Test
    void compileErrorsNameTheRule() {
        assertCompileError("rule for 'ssn': no decryptor named 'missing'; the decryptors are [pii, cards, fixed]",
                "ssn", "missing");
        assertCompileError("rule for 'a.b.c.d': invalid column pattern: a.b.c.d", "a.b.c.d", "pii");
    }

    private static void assertCompileError(String expected, String pattern, String decryptor) {
        List<Rules.Element> elements = List.of(new Rules.Element(pattern, decryptor));
        assertEquals(expected, assertThrows(IllegalArgumentException.class,
                () -> Rules.compile(elements, Decryptors.parse(Fixtures.DECRYPTORS))).getMessage());
    }

    @Test
    void columnMatchesNameLabelOrJoinedLabel() {
        ColumnMatcher ssn = ColumnMatcher.parse("ssn");
        assertTrue(ssn.matches(column("SSN", "SSN", "", "")));
        assertTrue(ssn.matches(column("social", "ssn", "", "")));
        assertTrue(ssn.matches(column("Customers - Customer__ssn", "Customers - Customer__ssn", "", "")));
        assertFalse(ssn.matches(column("ssn_2", "ssn_2", "", "")));
    }

    @Test
    void tableNarrowsTheMatchOnlyWhenTheDriverReportsIt() {
        ColumnMatcher pattern = ColumnMatcher.parse("dbo.customers.ssn");
        assertTrue(pattern.matches(column("ssn", "ssn", "", "")));
        assertTrue(pattern.matches(column("ssn", "ssn", "CUSTOMERS", "DBO")));
        assertFalse(pattern.matches(column("ssn", "ssn", "employees", "")));
        assertFalse(pattern.matches(column("ssn", "ssn", "customers", "archive")));
    }

    @Test
    void regexSearchesTheLabel() {
        ColumnMatcher pattern = ColumnMatcher.parse("/_enc$/");
        assertTrue(pattern.matches(column("ssn_ENC", "ssn", "", "")));
        assertFalse(pattern.matches(column("ssn", "ssn_enc", "", "")));
    }
}
