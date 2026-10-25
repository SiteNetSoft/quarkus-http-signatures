package org.sitenetsoft.httpsignatures;

import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

import org.sitenetsoft.httpsignatures.HttpSignatureException.Reason;

/**
 * The Cavage {@code Signature} header: {@code keyId="…",algorithm="…",headers="…",signature="…"} with optional
 * {@code created} and {@code expires}.
 */
public final class CavageSignature {

    private CavageSignature() {
    }

    public record Parsed(String keyId, Optional<String> algorithm, List<String> headers, byte[] signature,
            Optional<Long> created, Optional<Long> expires) {
    }

    public static Parsed parse(String headerValue) {
        Map<String, String> params = new LinkedHashMap<>();
        int i = 0;
        String s = headerValue == null ? "" : headerValue.strip();
        while (i < s.length()) {
            int eq = s.indexOf('=', i);
            if (eq < 0) {
                throw malformed("expected key=value");
            }
            String key = s.substring(i, eq).strip();
            i = eq + 1;
            String value;
            if (i < s.length() && s.charAt(i) == '"') {
                int end = i + 1;
                StringBuilder sb = new StringBuilder();
                while (end < s.length() && s.charAt(end) != '"') {
                    if (s.charAt(end) == '\\' && end + 1 < s.length()) {
                        end++;
                    }
                    sb.append(s.charAt(end));
                    end++;
                }
                if (end >= s.length()) {
                    throw malformed("unterminated quoted value");
                }
                value = sb.toString();
                i = end + 1;
            } else {
                int end = s.indexOf(',', i);
                if (end < 0) {
                    end = s.length();
                }
                value = s.substring(i, end).strip();
                i = end;
            }
            params.put(key, value);
            while (i < s.length() && (s.charAt(i) == ',' || s.charAt(i) == ' ')) {
                i++;
            }
        }
        String keyId = params.get("keyId");
        String signature = params.get("signature");
        if (keyId == null || keyId.isEmpty() || signature == null) {
            throw malformed("keyId and signature are required");
        }
        byte[] sig;
        try {
            sig = Base64.getDecoder().decode(signature);
        } catch (IllegalArgumentException e) {
            throw malformed("signature is not base64");
        }
        List<String> headers = new ArrayList<>();
        String h = params.getOrDefault("headers", "date");
        for (String part : h.strip().split("\\s+")) {
            if (!part.isEmpty()) {
                headers.add(part.toLowerCase(Locale.ROOT));
            }
        }
        return new Parsed(keyId, Optional.ofNullable(params.get("algorithm")), headers, sig,
                number(params.get("created")), number(params.get("expires")));
    }

    private static Optional<Long> number(String v) {
        if (v == null) {
            return Optional.empty();
        }
        try {
            return Optional.of((long) Double.parseDouble(v));
        } catch (NumberFormatException e) {
            throw malformed("bad numeric parameter");
        }
    }

    public static String serialize(String keyId, String algorithm, List<String> headers, byte[] signature,
            Optional<Long> created, Optional<Long> expires) {
        StringBuilder sb = new StringBuilder();
        sb.append("keyId=\"").append(keyId).append("\",algorithm=\"").append(algorithm).append('"');
        created.ifPresent(c -> sb.append(",created=").append(c));
        expires.ifPresent(e -> sb.append(",expires=").append(e));
        sb.append(",headers=\"").append(String.join(" ", headers)).append('"');
        sb.append(",signature=\"").append(Base64.getEncoder().encodeToString(signature)).append('"');
        return sb.toString();
    }

    private static HttpSignatureException malformed(String what) {
        return new HttpSignatureException(Reason.MALFORMED, "Malformed Cavage Signature header: " + what);
    }
}
