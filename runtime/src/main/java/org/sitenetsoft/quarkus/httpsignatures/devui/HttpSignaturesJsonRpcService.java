package org.sitenetsoft.quarkus.httpsignatures.devui;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import jakarta.inject.Inject;

import org.sitenetsoft.httpsignatures.Headers;
import org.sitenetsoft.httpsignatures.HttpMessageView;
import org.sitenetsoft.httpsignatures.HttpSignatureException;
import org.sitenetsoft.httpsignatures.HttpVerifier;
import org.sitenetsoft.httpsignatures.VerificationPolicy;
import org.sitenetsoft.httpsignatures.VerificationResult;
import org.sitenetsoft.quarkus.httpsignatures.HttpSignaturesConfig;
import org.sitenetsoft.quarkus.httpsignatures.StaticKeys;
import org.sitenetsoft.quarkus.httpsignatures.VerificationPolicies;

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

/**
 * Dev UI backend: shows the policy in effect and verifies a pasted raw request, printing its signature base.
 */
public class HttpSignaturesJsonRpcService {

    @Inject
    HttpSignaturesConfig config;

    @Inject
    VerificationPolicies policies;

    @Inject
    StaticKeys keys;

    public JsonObject policy() {
        VerificationPolicy p = policies.current();
        return new JsonObject()
                .put("schemes", new JsonArray(p.schemes().stream().map(s -> s.id()).toList()))
                .put("clockSkew", p.clockSkew().toString())
                .put("maxAge", p.maxAge().toString())
                .put("requireDigest", p.requireDigest())
                .put("nonceEnabled", config.nonce().enabled())
                .put("preferredScheme", config.sign().preferredScheme().id())
                .put("fallback", config.sign().fallback())
                .put("paths", new JsonArray(config.verify().paths().orElse(List.of())))
                .put("staticKeys", new JsonArray(new ArrayList<>(keys.ids())));
    }

    /**
     * @param rawRequest {@code METHOD /path HTTP/1.1}, header lines, a blank line, then the body
     * @param baseUrl scheme and authority to resolve the target against, for example {@code https://example.com}
     */
    public JsonObject verify(String rawRequest, String baseUrl) {
        JsonObject out = new JsonObject();
        HttpMessageView msg;
        try {
            msg = parse(rawRequest, baseUrl);
        } catch (RuntimeException e) {
            return out.put("ok", false).put("reason", "UNPARSEABLE").put("message", e.getMessage());
        }
        out.put("signatureBase", HttpVerifier.signatureBase(msg).orElse(null));
        try {
            VerificationResult r = new HttpVerifier().verify(msg, policies.current());
            return out.put("ok", true).put("scheme", r.scheme().id()).put("keyId", r.keyId()).put("algorithm", r.alg().id())
                    .put("covered", new JsonArray(r.covered().stream().map(c -> c.serialized()).toList()));
        } catch (HttpSignatureException e) {
            return out.put("ok", false).put("reason", e.reason().name()).put("message", e.getMessage());
        }
    }

    static HttpMessageView parse(String raw, String baseUrl) {
        String[] parts = raw.replace("\r\n", "\n").split("\n\n", 2);
        String[] lines = parts[0].split("\n");
        String[] requestLine = lines[0].trim().split("\\s+");
        if (requestLine.length < 2) {
            throw new IllegalArgumentException("first line must be 'METHOD /target'");
        }
        Map<String, List<String>> headers = new LinkedHashMap<>();
        for (int i = 1; i < lines.length; i++) {
            int colon = lines[i].indexOf(':');
            if (colon > 0) {
                headers.computeIfAbsent(lines[i].substring(0, colon).trim(), k -> new ArrayList<>()).add(lines[i].substring(colon + 1).trim());
            }
        }
        String target = requestLine[1];
        URI uri = target.startsWith("http") ? URI.create(target)
                : URI.create((baseUrl == null || baseUrl.isBlank() ? "http://localhost:8080" : baseUrl.replaceAll("/$", "")) + target);
        byte[] body = parts.length > 1 && !parts[1].isEmpty() ? parts[1].getBytes(StandardCharsets.UTF_8) : null;
        return HttpMessageView.of(requestLine[0], uri, Headers.of(headers), body);
    }
}
