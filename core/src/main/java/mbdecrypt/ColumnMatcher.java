package mbdecrypt;

import java.util.ArrayDeque;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/** The left-hand side of a rule: which result columns it applies to. */
sealed interface ColumnMatcher {

    boolean matches(ColumnDescription column);

    /** Parses {@code /regex/} or {@code [schema.][table.]column} patterns */
    static ColumnMatcher parse(String text) throws IllegalArgumentException {
        if (text.startsWith("/")) {
            try {
                return new Regex(Pattern.compile(text.substring(1, text.length() - 1), Pattern.CASE_INSENSITIVE));
            } catch (PatternSyntaxException e) {
                throw new IllegalArgumentException("invalid regex %s: %s".formatted(text, e.getDescription()));
            }
        }

        var parts = new ArrayDeque<>(List.of(text.strip().split("\\s*\\.\\s*", -1)));
        var column = parts.pollLast();
        var table = parts.pollLast();
        var schema = parts.pollLast();

        if (parts.size() > 0) {
            throw new IllegalArgumentException("invalid column pattern: %s".formatted(text));
        }

        return new Qualified(schema, table, column);
    }

    record Qualified(String schema, String table, String column) implements ColumnMatcher {
        @Override
        public boolean matches(ColumnDescription c) {
            return columnMatches(c) && partMatches(table, c.table()) && partMatches(schema, c.schema());
        }

        private boolean columnMatches(ColumnDescription c) {
            if (column.equalsIgnoreCase(c.name()) || column.equalsIgnoreCase(c.label())) {
                return true;
            }
            int join = c.label().lastIndexOf("__");
            return join >= 0 && column.equalsIgnoreCase(c.label().substring(join + 2));
        }

        private static boolean partMatches(String expected, String actual) {
            return expected == null || actual.isEmpty() || expected.equalsIgnoreCase(actual);
        }
    }

    record Regex(Pattern regex) implements ColumnMatcher {
        @Override
        public boolean matches(ColumnDescription c) {
            return regex.matcher(c.label()).find();
        }
    }
}
