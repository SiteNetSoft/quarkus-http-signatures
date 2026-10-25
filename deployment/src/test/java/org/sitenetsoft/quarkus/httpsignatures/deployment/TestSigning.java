package org.sitenetsoft.quarkus.httpsignatures.deployment;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.sitenetsoft.httpsignatures.Algorithm;
import org.sitenetsoft.httpsignatures.Headers;
import org.sitenetsoft.httpsignatures.HttpMessageView;
import org.sitenetsoft.httpsignatures.HttpSigner;
import org.sitenetsoft.httpsignatures.Keys;
import org.sitenetsoft.httpsignatures.Scheme;
import org.sitenetsoft.httpsignatures.SignatureSpec;
import org.sitenetsoft.httpsignatures.SignedHeaders;
import org.sitenetsoft.httpsignatures.SigningKey;

/**
 * Signs test requests with the Ed25519 key from {@code keys/ed25519.pem} (key id {@code k1}).
 */
final class TestSigning {

    static final String KEY_ID = "k1";

    static SigningKey key() {
        List<Key> keys = Keys.parsePemAll(resource("keys/ed25519.pem"));
        Key priv = keys.stream().filter(java.security.PrivateKey.class::isInstance).findFirst().orElseThrow();
        return new SigningKey(KEY_ID, Algorithm.ED25519, priv);
    }

    static String resource(String name) {
        try (var in = TestSigning.class.getClassLoader().getResourceAsStream(name)) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (java.io.IOException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Headers to add to a request so the server accepts it. Includes Host, Date, Content-Type and the digest.
     */
    static Map<String, String> sign(Scheme scheme, String method, String url, String body) {
        return sign(scheme, method, url, body, null);
    }

    static Map<String, String> sign(Scheme scheme, String method, String url, String body, List<String> components) {
        URI uri = URI.create(url);
        byte[] bytes = body == null ? null : body.getBytes(StandardCharsets.UTF_8);
        Map<String, List<String>> h = new LinkedHashMap<>();
        h.put("Host", List.of(uri.getPort() == -1 ? uri.getHost() : uri.getHost() + ":" + uri.getPort()));
        h.put("Content-Type", List.of("application/json"));
        HttpMessageView msg = HttpMessageView.of(method, uri, Headers.of(h), bytes);
        SignatureSpec spec = scheme == Scheme.RFC9421
                ? SignatureSpec.rfc9421(KEY_ID, Algorithm.ED25519, Instant.now(), bytes != null)
                : SignatureSpec.cavage(KEY_ID, Algorithm.ED25519, Instant.now(), bytes != null);
        if (components != null) {
            spec = spec.withCovered(components.stream().map(org.sitenetsoft.httpsignatures.Component::of).toList());
        }
        SignedHeaders signed = new HttpSigner().sign(msg, spec, key());
        Map<String, String> out = new LinkedHashMap<>();
        out.put("Host", h.get("Host").get(0));
        out.put("Content-Type", "application/json");
        signed.headers().forEach(out::put);
        return out;
    }
}
