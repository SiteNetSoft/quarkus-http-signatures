package org.sitenetsoft.httpsignatures;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * A covered component: a lowercased header name or a derived component such as {@code @method}, with optional
 * parameters (for example {@code @query-param;name="Pet"}).
 */
public record Component(String name, Map<String, String> params) {

    public Component {
        if (name == null || name.isEmpty()) {
            throw new IllegalArgumentException("component name is empty");
        }
        name = name.toLowerCase(Locale.ROOT);
        params = params == null ? Map.of() : Collections.unmodifiableMap(new LinkedHashMap<>(params));
    }

    public static Component of(String name) {
        return new Component(name, Map.of());
    }

    public Component withParam(String key, String value) {
        Map<String, String> p = new LinkedHashMap<>(params);
        p.put(key, value);
        return new Component(name, p);
    }

    public boolean isDerived() {
        return name.startsWith("@");
    }

    /**
     * The component identifier as it appears in a signature base line and in {@code Signature-Input}.
     */
    public String serialized() {
        StringBuilder sb = new StringBuilder("\"").append(name).append('"');
        for (Map.Entry<String, String> e : params.entrySet()) {
            sb.append(';').append(e.getKey());
            if (e.getValue() != null) {
                sb.append("=\"").append(e.getValue().replace("\\", "\\\\").replace("\"", "\\\"")).append('"');
            }
        }
        return sb.toString();
    }

    @Override
    public String toString() {
        return serialized();
    }
}
