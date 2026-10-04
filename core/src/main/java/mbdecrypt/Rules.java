package mbdecrypt;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlElementWrapper;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/** Defines decryption rules and plans columns for decryption based on them. */
public final class Rules {
    private static final Pattern PREFIX = Pattern.compile("decrypt_([a-z0-9]+)_.+", Pattern.CASE_INSENSITIVE);

    private final List<ConfiguredRule> rules;
    private final Decryptors decryptors;

    private record ConfiguredRule(ColumnMatcher matcher, Rule rule) {
    }

    /**
     * A {@code <rule>} element defined in the configuration.
     *
     * @param pattern   {@code [schema.][table.]column} or {@code /regex/}; see
     *                  {@link ColumnMatcher#parse}
     * @param decryptor the name of the decryptor to be used
     */
    record Element(String pattern, String decryptor) {
    }

    record Elements(
            @JacksonXmlElementWrapper(useWrapping = false) @JacksonXmlProperty(localName = "rule") List<Element> rules) {
    }

    private Rules(List<ConfiguredRule> rules, Decryptors decryptors) {
        this.rules = List.copyOf(rules);
        this.decryptors = decryptors;
    }

    public static Rules parse(String xml, Decryptors decryptors) throws IllegalArgumentException {
        return compile(elements(xml), decryptors);
    }

    static List<Element> elements(String xml) throws IllegalArgumentException {
        if (xml == null || xml.isBlank()) {
            return List.of();
        }

        List<Element> elements;
        try {
            elements = Xml.parse(xml, Elements.class).rules();
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException(
                    "Encrypted columns in the connection settings aren't valid XML (line %d): %s"
                            .formatted(e.getLocation().getLineNr(), e.getOriginalMessage()),
                    e);
        }

        if (elements == null) {
            return List.of();
        }

        for (Element rule : elements) {
            if (rule.pattern() == null || rule.decryptor() == null) {
                throw new IllegalArgumentException("every rule needs a pattern and a decryptor: " + rule);
            }
        }

        return elements;
    }

    static Rules compile(List<Element> elements, Decryptors decryptors) throws IllegalArgumentException {
        List<ConfiguredRule> rules = new ArrayList<>();

        for (var element : elements) {
            try {
                var matcher = ColumnMatcher.parse(element.pattern());
                var rule = new Rule(element.pattern(), decryptors.get(element.decryptor()), false);
                rules.add(new ConfiguredRule(matcher, rule));
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("rule for '%s': %s".formatted(element.pattern(), e.getMessage()), e);
            }
        }

        return new Rules(rules, decryptors);
    }

    /**
     * Prepares a plan for all columns that need to be decrypted, returns null if no
     * columns need decrypting.
     */
    public ColumnDecryptor[] plan(ResultSetMetaData md) throws SQLException {
        int count = md.getColumnCount();
        ColumnDecryptor[] plan = null;

        for (int i = 1; i <= count; i++) {
            var column = ColumnDescription.of(md, i);
            var rule = columnPrefixRule(column.label());

            for (int r = 0; rule == null && r < rules.size(); r++) {
                if (rules.get(r).matcher().matches(column)) {
                    rule = rules.get(r).rule();
                }
            }

            if (rule != null) {
                if (plan == null) {
                    plan = new ColumnDecryptor[count + 1];
                }
                plan[i] = new ColumnDecryptor(rule, column);
            }
        }

        return plan;
    }

    /** Try to get a rule from the column's name prefix, if it's prefixed */
    private Rule columnPrefixRule(String label) throws SQLException {
        var m = PREFIX.matcher(label);
        if (!m.matches())
            return null;
        var decryptorName = m.group(1);
        try {
            return new Rule("decrypt_" + decryptorName + "_*", decryptors.get(decryptorName), true);
        } catch (IllegalArgumentException e) {
            throw new SQLException("column '%s': %s".formatted(label, e.getMessage()), e);
        }
    }
}
