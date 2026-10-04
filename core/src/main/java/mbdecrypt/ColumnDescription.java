package mbdecrypt;

import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Types;

/**
 * The column information provided by JDBC.
 *
 * @param label    the column's alias or name
 * @param name     the column's name SQL Server reports the alias here too
 * @param table    the column's table
 * @param schema   the table's schema
 * @param jdbcType a {@link java.sql.Types} constant
 */
public record ColumnDescription(String label, String name, String table, String schema, int jdbcType) {

    static ColumnDescription of(ResultSetMetaData md, int column) throws SQLException {
        return new ColumnDescription(
                orEmpty(md.getColumnLabel(column)),
                orEmpty(md.getColumnName(column)),
                optional(() -> md.getTableName(column)),
                optional(() -> md.getSchemaName(column)),
                md.getColumnType(column));
    }

    boolean isBinary() {
        return switch (jdbcType) {
            case Types.BINARY, Types.VARBINARY, Types.LONGVARBINARY, Types.BLOB -> true;
            default -> false;
        };
    }

    private interface MetaDataCall {
        String get() throws SQLException;
    }

    private static String optional(MetaDataCall call) {
        try {
            return orEmpty(call.get());
        } catch (SQLException | RuntimeException e) {
            return "";
        }
    }

    private static String orEmpty(String value) {
        return value == null ? "" : value;
    }
}
