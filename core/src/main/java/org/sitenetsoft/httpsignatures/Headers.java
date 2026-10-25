package org.sitenetsoft.httpsignatures;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;

/**
 * Case-insensitive read-only view of HTTP header fields.
 */
public interface Headers {

    /**
     * All values of a field, in order; empty when absent.
     */
    List<String> values(String name);

    Set<String> names();

    default Optional<String> first(String name) {
        List<String> v = values(name);
        return v.isEmpty() ? Optional.empty() : Optional.of(v.get(0));
    }

    default boolean contains(String name) {
        return !values(name).isEmpty();
    }

    /**
     * The field value as RFC 9421 section 2.1 canonicalizes it: each value trimmed, inner whitespace runs collapsed
     * to one space, values joined with {@code ", "}.
     */
    default String combined(String name) {
        List<String> parts = new ArrayList<>();
        for (String v : values(name)) {
            parts.add(v.strip().replaceAll("[ \\t]+", " "));
        }
        return String.join(", ", parts);
    }

    static Headers of(Map<String, ? extends Collection<String>> map) {
        TreeMap<String, List<String>> ci = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        map.forEach((k, v) -> ci.computeIfAbsent(k, x -> new ArrayList<>()).addAll(v));
        return new Headers() {
            @Override
            public List<String> values(String name) {
                List<String> v = ci.get(name);
                return v == null ? List.of() : List.copyOf(v);
            }

            @Override
            public Set<String> names() {
                return Set.copyOf(ci.keySet());
            }
        };
    }

    static Headers empty() {
        return of(Map.of());
    }
}
