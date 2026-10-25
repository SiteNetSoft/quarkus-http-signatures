package org.sitenetsoft.httpsignatures;

/**
 * The two signature schemes in use: RFC 9421 ({@code Signature-Input} + {@code Signature}) and the older Cavage
 * draft 12 (a lone {@code Signature} header).
 */
public enum Scheme {
    RFC9421("rfc9421"),
    CAVAGE("cavage");

    private final String id;

    Scheme(String id) {
        this.id = id;
    }

    public String id() {
        return id;
    }

    public static Scheme fromId(String id) {
        for (Scheme s : values()) {
            if (s.id.equalsIgnoreCase(id)) {
                return s;
            }
        }
        throw new IllegalArgumentException("Unknown signature scheme: " + id + " (expected rfc9421 or cavage)");
    }

    public Scheme other() {
        return this == RFC9421 ? CAVAGE : RFC9421;
    }
}
