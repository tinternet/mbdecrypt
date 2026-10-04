package mbdecrypt.jdbc;

import java.sql.Connection;
import java.sql.Driver;
import java.sql.DriverManager;
import java.sql.DriverPropertyInfo;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.util.Properties;
import java.util.logging.Logger;
import mbdecrypt.Decryptors;
import mbdecrypt.Rules;

/**
 * A JDBC driver that wraps another JDBC driver and decrypts columns in the results based on configured rules.
 *
 * <p>URLs include {@code decrypt:} after {@code jdbc:}, e.g. {@code jdbc:decrypt:sqlserver://host}.
 * 
 * The named decryptors are XML in the {@code decrypt-decryptors} connection property (see {@link Decryptors}), and
 * optional rules in {@code decrypt-rules} (see {@link Rules}).
 */
public final class DecryptingDriver implements Driver {
    public static final String URL_PREFIX = "jdbc:decrypt:";
    public static final String ENCRYPTION_RULES_CONFIG = "decrypt-rules";
    public static final String DECRYPTORS_CONFIG = "decrypt-decryptors";

    @Override
    public boolean acceptsURL(String url) {
        return url != null && url.startsWith(URL_PREFIX);
    }

    @Override
    public Connection connect(String url, Properties info) throws SQLException {
        if (!acceptsURL(url)) {
            return null;
        }
        
        Rules rules;

        try {
            rules = Rules.parse(info.getProperty(ENCRYPTION_RULES_CONFIG),
                    Decryptors.parse(info.getProperty(DECRYPTORS_CONFIG)));
        } catch (IllegalArgumentException e) {
            throw new SQLException(e.getMessage(), e);
        }

        // don't pass custom config to the parent driver.
        Properties parentInfo = (Properties) info.clone();
        parentInfo.remove(ENCRYPTION_RULES_CONFIG);
        parentInfo.remove(DECRYPTORS_CONFIG);

        String targetUrl = url.replaceFirst("^" + URL_PREFIX, "jdbc:");
        return DriverProxy.connection(DriverManager.getConnection(targetUrl, parentInfo), rules);
    }

    @Override
    public DriverPropertyInfo[] getPropertyInfo(String url, Properties info) {
        return new DriverPropertyInfo[0];
    }

    @Override
    public int getMajorVersion() {
        return 0;
    }

    @Override
    public int getMinorVersion() {
        return 1;
    }

    @Override
    public boolean jdbcCompliant() {
        return false;
    }

    @Override
    public Logger getParentLogger() throws SQLFeatureNotSupportedException {
        throw new SQLFeatureNotSupportedException();
    }
}
