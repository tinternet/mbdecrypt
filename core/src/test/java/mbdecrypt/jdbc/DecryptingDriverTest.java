package mbdecrypt.jdbc;

import static mbdecrypt.Fixtures.CARDS_KEY;
import static mbdecrypt.Fixtures.PII_KEY;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Types;
import java.util.HexFormat;
import java.util.Properties;
import mbdecrypt.Fixtures;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class DecryptingDriverTest {
    private static final String H2 = "h2:mem:decrypting;DB_CLOSE_DELAY=-1";
    private static final String RULES = """
            <rule pattern="customers.ssn" decryptor="pii"/>
            <rule pattern="customers.card" decryptor="cards"/>
            <rule pattern="/_enc$/" decryptor="pii"/>
            """;

    @BeforeAll
    static void createDatabase() throws Exception {
        Class.forName(DecryptingDriver.class.getName());
        try (Connection c = DriverManager.getConnection("jdbc:" + H2);
                Statement s = c.createStatement()) {
            s.execute("CREATE TABLE customers (id INT, name VARCHAR(50), ssn VARCHAR(200), card VARBINARY(200))");
            try (PreparedStatement insert = c.prepareStatement("INSERT INTO customers VALUES (?, ?, ?, ?)")) {
                insert.setInt(1, 1);
                insert.setString(2, "Ada");
                insert.setString(3, Fixtures.base64(Fixtures.gcm(PII_KEY, "123-45-6789")));
                insert.setBytes(4, Fixtures.cbc(CARDS_KEY, "4111111111111111"));
                insert.executeUpdate();

                insert.setInt(1, 2);
                insert.setString(2, "Bob");
                insert.setNull(3, Types.VARCHAR);
                insert.setNull(4, Types.VARBINARY);
                insert.executeUpdate();

                insert.setInt(1, 3);
                insert.setString(2, "Cy");
                insert.setString(3, "not encrypted");
                insert.setBytes(4, new byte[] {1, 2, 3});
                insert.executeUpdate();
            }
            s.execute("CREATE TABLE employees (id INT, ssn VARCHAR(200))");
            s.execute("INSERT INTO employees VALUES (1, '987-65-4321')");
            s.execute("CREATE TABLE notes (body VARCHAR(200))");
            s.execute("INSERT INTO notes VALUES ('" + Fixtures.base64(Fixtures.gcm(PII_KEY, "hello")) + "')");
        }
    }

    private static Connection connect() throws SQLException {
        Properties info = new Properties();
        info.setProperty("decrypt-rules", RULES);
        info.setProperty("decrypt-decryptors", Fixtures.DECRYPTORS);
        return DriverManager.getConnection("jdbc:decrypt:" + H2, info);
    }

    @Test
    void decryptsTheColumnsTheRulesName() throws Exception {
        try (Connection c = connect();
                Statement s = c.createStatement();
                ResultSet rs = s.executeQuery("SELECT id, name, ssn, card FROM customers ORDER BY id")) {
            rs.next();
            assertEquals("Ada", rs.getString("name"));
            assertEquals("123-45-6789", rs.getString("ssn"));
            assertEquals("123-45-6789", rs.getObject(3));
            assertEquals("4111111111111111", rs.getObject("card"));
            assertEquals("4111111111111111", rs.getObject(4, String.class));

            rs.next();
            assertNull(rs.getObject("ssn"));
            assertTrue(rs.wasNull());
            assertNull(rs.getString("card"));
        }
    }

    @Test
    void reportsDecryptedColumnsAsText() throws Exception {
        try (Connection c = connect();
                PreparedStatement s = c.prepareStatement("SELECT id, card FROM customers");
                ResultSet rs = s.executeQuery()) {
            ResultSetMetaData md = rs.getMetaData();
            assertEquals(Types.INTEGER, md.getColumnType(1));
            assertEquals(Types.NVARCHAR, md.getColumnType(2));
            assertEquals("nvarchar", md.getColumnTypeName(2));
            assertEquals(String.class.getName(), md.getColumnClassName(2));
            assertEquals("CARD", md.getColumnLabel(2));
        }
    }

    @Test
    void valuesThatDontDecryptAreReturnedAsStored() throws Exception {
        try (Connection c = connect();
                Statement s = c.createStatement();
                ResultSet rs = s.executeQuery("SELECT ssn, card FROM customers WHERE id = 3")) {
            rs.next();
            assertEquals("not encrypted", rs.getString(1));
            assertEquals("0x010203", rs.getString(2));
        }
    }

    @Test
    void prefixedValuesThatDontDecryptShowWhy() throws Exception {
        try (Connection c = connect();
                Statement s = c.createStatement();
                ResultSet rs = s.executeQuery("SELECT ssn AS decrypt_cards_ssn, card AS decrypt_cards_card, "
                        + "'#' AS decrypt_pii_x FROM customers WHERE id IN (1, 3) ORDER BY id")) {
            rs.next();
            assertTrue(rs.getString(1).startsWith("[can't decrypt: wrong key or algorithm, or not encrypted ("));
            rs.next();
            assertEquals("[can't decrypt: wrong key or algorithm, or not encrypted (value is too short to be an IV "
                    + "followed by AES-CBC ciphertext)]", rs.getString(2));
            assertEquals("[can't decrypt: the value isn't hex or Base64]", rs.getString(3));
        }
    }

    @Test
    void tableQualifiedRulesSkipOtherTablesWhenTheDriverReportsTables() throws Exception {
        try (Connection c = connect();
                Statement s = c.createStatement();
                ResultSet rs = s.executeQuery("SELECT ssn FROM employees")) {
            rs.next();
            assertEquals("987-65-4321", rs.getString(1));
        }
    }

    @Test
    void labelRegexRulesMatchAliases() throws Exception {
        try (Connection c = connect();
                Statement s = c.createStatement()) {
            assertTrue(s.execute("SELECT body AS body_enc, body FROM notes"));
            try (ResultSet rs = s.getResultSet()) {
                rs.next();
                assertEquals("hello", rs.getString("body_enc"));
                assertTrue(rs.getString("body").length() > 20, "not decrypted without the alias");
            }
        }
    }

    @Test
    void prefixedLabelsNameTheDecryptor() throws Exception {
        try (Connection c = connect();
                Statement s = c.createStatement();
                ResultSet rs = s.executeQuery("SELECT card AS decrypt_cards_card, "
                        + "card AS \"Orders - Customer__DECRYPT_Cards_x\", "
                        + "name AS first_name FROM customers WHERE id = 1")) {
            rs.next();
            assertEquals("4111111111111111", rs.getString(1));
            assertEquals("4111111111111111", rs.getString(2));
            assertEquals("Ada", rs.getString(3));
        }
    }

    @Test
    void prefixWithAnUnknownDecryptorFailsTheQuery() throws Exception {
        try (Connection c = connect();
                Statement s = c.createStatement()) {
            assertEquals("column 'DECRYPT_NOPE_SSN': no decryptor named 'NOPE'; the decryptors are [pii, cards, fixed]",
                    assertThrows(SQLException.class,
                            () -> s.executeQuery("SELECT ssn AS decrypt_nope_ssn FROM customers"))
                            .getMessage());
        }
    }

    @Test
    void decryptorsWithAnIvDecryptValuesStoredWithoutOne() throws Exception {
        String hex = HexFormat.of().formatHex(Fixtures.cbc(PII_KEY, Fixtures.FIXED_IV, "hello"));
        try (Connection c = connect();
                Statement s = c.createStatement();
                ResultSet rs = s.executeQuery("SELECT '" + hex + "' AS decrypt_fixed_greeting")) {
            rs.next();
            assertEquals("hello", rs.getString(1));
        }
    }

    @Test
    void textColumnsCanHoldHex() throws Exception {
        String hex = HexFormat.of().formatHex(Fixtures.gcm(PII_KEY, "hello"));
        try (Connection c = connect();
                Statement s = c.createStatement();
                ResultSet rs = s.executeQuery("SELECT '" + hex + "' AS a_enc, '0x" + hex.toUpperCase() + "' AS b_enc")) {
            rs.next();
            assertEquals("hello", rs.getString(1));
            assertEquals("hello", rs.getString(2));
        }
    }

    @Test
    void misconfigurationFailsTheConnection() {
        assertEquals("rule for 'ssn': no decryptor named 'missing'; the decryptors are [pii, cards, fixed]",
                connectionError(Fixtures.DECRYPTORS, "<rule pattern=\"ssn\" decryptor=\"missing\"/>"));
        assertTrue(connectionError(null, RULES).startsWith("no decryptors are configured"));
    }

    private static String connectionError(String decryptors, String rules) {
        Properties info = new Properties();
        info.setProperty("decrypt-rules", rules);
        if (decryptors != null) {
            info.setProperty("decrypt-decryptors", decryptors);
        }
        return assertThrows(SQLException.class, () -> DriverManager.getConnection("jdbc:decrypt:" + H2, info))
                .getMessage();
    }

    /** Connection pools pass the same properties for every connection they open. */
    @Test
    void leavesTheCallersPropertiesAlone() throws Exception {
        Properties info = new Properties();
        info.setProperty("decrypt-rules", RULES);
        info.setProperty("decrypt-decryptors", Fixtures.DECRYPTORS);
        DriverManager.getConnection("jdbc:decrypt:" + H2, info).close();
        assertEquals(RULES, info.getProperty("decrypt-rules"));
    }
}
