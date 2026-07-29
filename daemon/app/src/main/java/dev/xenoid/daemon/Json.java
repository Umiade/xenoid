package dev.xenoid.daemon;

import java.util.*;

final class Json {
    static String quote(String s) { return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n") + "\""; }
    static String stringify(Object o) {
        if (o == null) return "null";
        if (o instanceof Boolean || o instanceof Number) return String.valueOf(o);
        if (o instanceof Map) {
            StringBuilder b = new StringBuilder("{"); boolean first = true;
            for (Object e0 : ((Map<?,?>) o).entrySet()) { Map.Entry<?,?> e = (Map.Entry<?,?>) e0; if (!first) b.append(','); first=false; b.append(quote(String.valueOf(e.getKey()))).append(':').append(stringify(e.getValue())); }
            return b.append('}').toString();
        }
        if (o instanceof Iterable) {
            StringBuilder b = new StringBuilder("["); boolean first = true;
            for (Object v : (Iterable<?>) o) { if (!first) b.append(','); first=false; b.append(stringify(v)); }
            return b.append(']').toString();
        }
        return quote(String.valueOf(o));
    }
}
