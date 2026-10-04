package mbdecrypt.jdbc;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.Statement;
import java.sql.Types;
import java.util.Set;
import mbdecrypt.ColumnDecryptor;
import mbdecrypt.Rules;

final class DriverProxy {
    private static final Set<String> GETTERS = Set.of("getObject", "getString", "getNString");

    private DriverProxy() {}

    static Connection connection(Connection connection, Rules rules) {
        return (Connection) wrapping(Connection.class, connection, rules);
    }

    private static Object wrapping(Class<?> type, Object target, Rules rules) {
        return proxy(type, (proxy, method, args) -> {
            Object result = forward(proxy, method, args, target);
            if (result instanceof Statement) {
                return wrapping(method.getReturnType(), result, rules);
            }
            if (result instanceof ResultSet rs) {
                ColumnDecryptor[] plan = rules.plan(rs.getMetaData());
                return plan == null ? rs : decrypting(rs, plan);
            }
            return result;
        });
    }

    private static ResultSet decrypting(ResultSet rs, ColumnDecryptor[] plan) {
        return (ResultSet) proxy(ResultSet.class, (proxy, method, args) -> {
            if (method.getName().equals("getMetaData")) {
                return metaData(rs.getMetaData(), plan);
            }
            if (GETTERS.contains(method.getName())) {
                int i = args[0] instanceof Integer index ? index : rs.findColumn((String) args[0]);
                if (i > 0 && i < plan.length && plan[i] != null) {
                    return plan[i].read(rs, i);
                }
            }
            return forward(proxy, method, args, rs);
        });
    }

    private static ResultSetMetaData metaData(ResultSetMetaData md, ColumnDecryptor[] plan) {
        return (ResultSetMetaData) proxy(ResultSetMetaData.class, (proxy, method, args) -> {
            if (args != null && args[0] instanceof Integer i && i > 0 && i < plan.length && plan[i] != null) {
                Object replaced = switch (method.getName()) {
                    case "getColumnType" -> Types.NVARCHAR;
                    case "getColumnTypeName" -> "nvarchar";
                    case "getColumnClassName" -> String.class.getName();
                    default -> null;
                };
                if (replaced != null) {
                    return replaced;
                }
            }
            return forward(proxy, method, args, md);
        });
    }

    private static Object forward(Object proxy, Method method, Object[] args, Object target) throws Throwable {
        if (method.getName().equals("equals")) {
            return proxy == args[0];
        }
        try {
            return method.invoke(target, args);
        } catch (InvocationTargetException e) {
            throw e.getCause();
        }
    }

    private static Object proxy(Class<?> type, InvocationHandler handler) {
        return Proxy.newProxyInstance(DriverProxy.class.getClassLoader(), new Class<?>[] {type}, handler);
    }
}
