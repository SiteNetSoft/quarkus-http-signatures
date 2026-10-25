package org.sitenetsoft.httpsignatures;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

import org.sitenetsoft.httpsignatures.HttpSignatureException.Reason;

/**
 * Builds the string that is signed, for both schemes.
 */
public final class SignatureBase {

    private SignatureBase() {
    }

    /**
     * RFC 9421 section 2.5: one line per covered component, then the {@code @signature-params} line.
     */
    public static String rfc9421(HttpMessageView msg, List<Component> covered, String signatureParams) {
        StringBuilder sb = new StringBuilder();
        for (Component c : covered) {
            for (String value : componentValues(msg, c)) {
                sb.append(c.serialized()).append(": ").append(value).append('\n');
            }
        }
        sb.append("\"@signature-params\": ").append(signatureParams);
        return sb.toString();
    }

    static List<String> componentValues(HttpMessageView msg, Component c) {
        if (!c.isDerived()) {
            if (!c.params().isEmpty()) {
                throw new HttpSignatureException(Reason.MALFORMED, "Unsupported component parameters on " + c.serialized());
            }
            if (!msg.headers().contains(c.name())) {
                throw new HttpSignatureException(Reason.MISSING_COMPONENT, "Covered header is absent: " + c.name());
            }
            return List.of(msg.headers().combined(c.name()));
        }
        URI uri = msg.targetUri();
        switch (c.name()) {
            case "@method":
                return List.of(requireRequest(msg, c).method().toUpperCase(Locale.ROOT));
            case "@target-uri":
                return List.of(requireUri(msg, c).toString());
            case "@authority":
                return List.of(authority(requireUri(msg, c)));
            case "@scheme":
                return List.of(requireUri(msg, c).getScheme().toLowerCase(Locale.ROOT));
            case "@request-target":
                return List.of(requestTarget(requireUri(msg, c)));
            case "@path":
                return List.of(path(requireUri(msg, c)));
            case "@query":
                return List.of("?" + Optional.ofNullable(requireUri(msg, c).getRawQuery()).orElse(""));
            case "@query-param":
                return queryParam(requireUri(msg, c), c);
            case "@status":
                if (msg.status().isEmpty()) {
                    throw new HttpSignatureException(Reason.MISSING_COMPONENT, "@status is only available on responses");
                }
                return List.of(Integer.toString(msg.status().getAsInt()));
            default:
                throw new HttpSignatureException(Reason.MALFORMED, "Unknown derived component " + c.name());
        }
    }

    private static HttpMessageView requireRequest(HttpMessageView msg, Component c) {
        if (!msg.isRequest()) {
            throw new HttpSignatureException(Reason.MISSING_COMPONENT, c.name() + " is only available on requests");
        }
        return msg;
    }

    private static URI requireUri(HttpMessageView msg, Component c) {
        if (msg.targetUri() == null) {
            throw new HttpSignatureException(Reason.MISSING_COMPONENT, c.name() + " needs a target URI");
        }
        return msg.targetUri();
    }

    static String authority(URI uri) {
        String host = uri.getHost();
        if (host == null) {
            throw new HttpSignatureException(Reason.MISSING_COMPONENT, "@authority needs a host");
        }
        host = host.toLowerCase(Locale.ROOT);
        int port = uri.getPort();
        boolean defaultPort = port == -1 || ("https".equalsIgnoreCase(uri.getScheme()) && port == 443)
                || ("http".equalsIgnoreCase(uri.getScheme()) && port == 80);
        return defaultPort ? host : host + ":" + port;
    }

    static String path(URI uri) {
        String p = uri.getRawPath();
        return p == null || p.isEmpty() ? "/" : p;
    }

    static String requestTarget(URI uri) {
        String q = uri.getRawQuery();
        return path(uri) + (q == null ? "" : "?" + q);
    }

    private static List<String> queryParam(URI uri, Component c) {
        String name = c.params().get("name");
        if (name == null) {
            throw new HttpSignatureException(Reason.MALFORMED, "@query-param needs a name parameter");
        }
        String query = uri.getRawQuery();
        List<String> values = new java.util.ArrayList<>();
        if (query != null) {
            for (String pair : query.split("&")) {
                int eq = pair.indexOf('=');
                String k = decode(eq < 0 ? pair : pair.substring(0, eq));
                if (k.equals(name)) {
                    values.add(encode(decode(eq < 0 ? "" : pair.substring(eq + 1))));
                }
            }
        }
        if (values.isEmpty()) {
            throw new HttpSignatureException(Reason.MISSING_COMPONENT, "Query parameter is absent: " + name);
        }
        return values;
    }

    private static String decode(String s) {
        return URLDecoder.decode(s.replace("+", "%2B"), StandardCharsets.UTF_8);
    }

    /**
     * RFC 3986 percent-encoding keeping unreserved characters, as RFC 9421 section 2.2.8 requires.
     */
    static String encode(String s) {
        StringBuilder sb = new StringBuilder();
        for (byte b : s.getBytes(StandardCharsets.UTF_8)) {
            char ch = (char) (b & 0xff);
            if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || "-._~".indexOf(ch) >= 0) {
                sb.append(ch);
            } else {
                sb.append('%').append(String.format("%02X", b & 0xff));
            }
        }
        return sb.toString();
    }

    /**
     * draft-cavage-http-signatures-12 section 2.3: {@code (request-target)}, {@code (created)}, {@code (expires)}
     * and lowercased header lines, joined with newlines.
     */
    public static String cavage(HttpMessageView msg, List<String> headers, Optional<Long> created, Optional<Long> expires) {
        StringBuilder sb = new StringBuilder();
        for (String h : headers) {
            String name = h.toLowerCase(Locale.ROOT);
            if (sb.length() > 0) {
                sb.append('\n');
            }
            switch (name) {
                case "(request-target)" -> sb.append("(request-target): ")
                        .append(msg.method().toLowerCase(Locale.ROOT)).append(' ').append(requestTarget(msg.targetUri()));
                case "(created)" -> sb.append("(created): ").append(created.orElseThrow(
                        () -> new HttpSignatureException(Reason.MISSING_COMPONENT, "(created) covered but no created parameter")));
                case "(expires)" -> sb.append("(expires): ").append(expires.orElseThrow(
                        () -> new HttpSignatureException(Reason.MISSING_COMPONENT, "(expires) covered but no expires parameter")));
                default -> {
                    if (!msg.headers().contains(name)) {
                        throw new HttpSignatureException(Reason.MISSING_COMPONENT, "Covered header is absent: " + name);
                    }
                    sb.append(name).append(": ").append(msg.headers().combined(name));
                }
            }
        }
        return sb.toString();
    }
}
