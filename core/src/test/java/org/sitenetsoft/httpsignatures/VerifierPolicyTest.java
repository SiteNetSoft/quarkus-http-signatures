package org.sitenetsoft.httpsignatures;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.sitenetsoft.httpsignatures.HttpSignatureException.Reason;

class VerifierPolicyTest {

    static KeyPair ed;
    static final Instant NOW = Instant.parse("2026-10-24T12:00:00Z");
    static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    static final byte[] BODY = "{\"event\":\"paid\"}".getBytes(StandardCharsets.UTF_8);

    @BeforeAll
    static void keys() throws Exception {
        ed = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    }

    static KeyResolver resolver() {
        return id -> "k1".equals(id) ? Optional.of(new VerificationKey("k1", Optional.empty(), ed.getPublic())) : Optional.empty();
    }

    static VerificationPolicy policy() {
        return VerificationPolicy.defaults(resolver()).withClock(CLOCK);
    }

    static HttpMessageView unsigned() {
        Map<String, List<String>> h = new LinkedHashMap<>();
        h.put("Host", List.of("hooks.example"));
        h.put("Content-Type", List.of("application/json"));
        return HttpMessageView.of("POST", URI.create("https://hooks.example/webhook"), Headers.of(h), BODY);
    }

    static HttpMessageView sign(SignatureSpec spec) {
        HttpMessageView msg = unsigned();
        SignedHeaders signed = new HttpSigner().sign(msg, spec, new SigningKey("k1", Algorithm.ED25519, ed.getPrivate()));
        Map<String, List<String>> h = new LinkedHashMap<>();
        msg.headers().names().forEach(n -> h.put(n, msg.headers().values(n)));
        signed.headers().forEach((k, v) -> h.put(k, List.of(v)));
        return HttpMessageView.of("POST", msg.targetUri(), Headers.of(h), BODY);
    }

    static HttpMessageView withHeaders(HttpMessageView msg, Map<String, String> replacements) {
        Map<String, List<String>> h = new LinkedHashMap<>();
        msg.headers().names().forEach(n -> h.put(n, msg.headers().values(n)));
        replacements.forEach((k, v) -> h.put(k, List.of(v)));
        return HttpMessageView.of(msg.method(), msg.targetUri(), Headers.of(h), msg.body().map(BodyDigest::body).orElse(null));
    }

    static Reason failure(HttpMessageView msg, VerificationPolicy policy) {
        return assertThrows(HttpSignatureException.class, () -> new HttpVerifier().verify(msg, policy)).reason();
    }

    @Test
    void defaultSpecVerifies() {
        VerificationResult r = new HttpVerifier().verify(sign(SignatureSpec.rfc9421("k1", Algorithm.ED25519, NOW, true)), policy());
        assertEquals("k1", r.keyId());
        assertEquals(List.of("@method", "@target-uri", "content-digest"), r.covered().stream().map(Component::name).toList());
    }

    @Test
    void tamperedBodyFails() {
        HttpMessageView msg = sign(SignatureSpec.rfc9421("k1", Algorithm.ED25519, NOW, true));
        HttpMessageView tampered = HttpMessageView.of("POST", msg.targetUri(), msg.headers(), "{\"event\":\"refund\"}".getBytes(StandardCharsets.UTF_8));
        assertEquals(Reason.DIGEST_MISMATCH, failure(tampered, policy()));
    }

    @Test
    void tamperedHeaderFailsSignature() {
        HttpMessageView msg = sign(SignatureSpec.rfc9421("k1", Algorithm.ED25519, NOW, true).withCovered(
                List.of(Component.of("@method"), Component.of("@target-uri"), Component.of("content-digest"), Component.of("content-type"))));
        assertEquals(Reason.INVALID_SIGNATURE, failure(withHeaders(msg, Map.of("Content-Type", "text/plain")), policy()));
    }

    @Test
    void wrongAlgorithmFails() {
        HttpMessageView msg = sign(SignatureSpec.rfc9421("k1", Algorithm.ED25519, NOW, true));
        String input = msg.headers().first("Signature-Input").orElseThrow().replace(";created=", ";alg=\"rsa-v1_5-sha256\";created=");
        assertEquals(Reason.ALGORITHM_KEY_MISMATCH, failure(withHeaders(msg, Map.of("Signature-Input", input)), policy()));
    }

    @Test
    void unknownAlgorithmFails() {
        HttpMessageView msg = sign(SignatureSpec.rfc9421("k1", Algorithm.ED25519, NOW, true));
        String input = msg.headers().first("Signature-Input").orElseThrow().replace(";created=", ";alg=\"md5\";created=");
        assertEquals(Reason.UNSUPPORTED_ALGORITHM, failure(withHeaders(msg, Map.of("Signature-Input", input)), policy()));
    }

    @Test
    void staleCreatedFails() {
        assertEquals(Reason.STALE, failure(sign(SignatureSpec.rfc9421("k1", Algorithm.ED25519, NOW.minusSeconds(7200), true)), policy()));
    }

    @Test
    void futureCreatedBeyondSkewFails() {
        assertEquals(Reason.FUTURE_CREATED, failure(sign(SignatureSpec.rfc9421("k1", Algorithm.ED25519, NOW.plusSeconds(600), true)), policy()));
        new HttpVerifier().verify(sign(SignatureSpec.rfc9421("k1", Algorithm.ED25519, NOW.plusSeconds(60), true)), policy());
    }

    @Test
    void expiredFails() {
        assertEquals(Reason.EXPIRED, failure(sign(SignatureSpec.rfc9421("k1", Algorithm.ED25519, NOW.minusSeconds(120), true)
                .withExpires(NOW.minusSeconds(1))), policy()));
    }

    @Test
    void missingCoveredComponentFails() {
        assertEquals(Reason.MISSING_COMPONENT, failure(sign(SignatureSpec.rfc9421("k1", Algorithm.ED25519, NOW, true)
                .withCovered(List.of(Component.of("@method")))), policy()));
    }

    @Test
    void policyRequiredComponentsAreEnforced() {
        VerificationPolicy strict = policy().withRequiredComponents(Set.of(Component.of("content-type")));
        assertEquals(Reason.MISSING_COMPONENT, failure(sign(SignatureSpec.rfc9421("k1", Algorithm.ED25519, NOW, true)), strict));
    }

    @Test
    void bodyWithoutDigestFailsWhenRequired() {
        HttpMessageView msg = sign(SignatureSpec.rfc9421("k1", Algorithm.ED25519, NOW, false));
        assertEquals(Reason.MISSING_COMPONENT, failure(msg, policy()));
        assertEquals(Reason.MISSING_DIGEST, failure(msg, policy().withStrictCoverage(false)));
        new HttpVerifier().verify(msg, policy().withStrictCoverage(false).withRequireDigest(false));
    }

    @Test
    void unknownKeyFails() {
        assertEquals(Reason.UNKNOWN_KEY, failure(sign(SignatureSpec.rfc9421("k1", Algorithm.ED25519, NOW, true)),
                policy().withKeys(id -> Optional.empty())));
    }

    @Test
    void replayFails() {
        Set<String> seen = new HashSet<>();
        VerificationPolicy withNonces = policy().withNonces((nonce, expires) -> seen.add(nonce));
        HttpMessageView msg = sign(SignatureSpec.rfc9421("k1", Algorithm.ED25519, NOW, true).withNonce("once"));
        new HttpVerifier().verify(msg, withNonces);
        assertEquals(Reason.REPLAY, failure(msg, withNonces));
    }

    @Test
    void schemeNotAllowedFails() {
        assertEquals(Reason.SCHEME_NOT_ALLOWED, failure(sign(SignatureSpec.rfc9421("k1", Algorithm.ED25519, NOW, true)),
                policy().withSchemes(Set.of(Scheme.CAVAGE))));
    }

    @Test
    void malformedSignatureInputFails() {
        HttpMessageView msg = sign(SignatureSpec.rfc9421("k1", Algorithm.ED25519, NOW, true));
        assertEquals(Reason.MALFORMED, failure(withHeaders(msg, Map.of("Signature-Input", "sig1=(\"@method")), policy()));
        assertEquals(Reason.MALFORMED, failure(withHeaders(msg, Map.of("Signature", "garbage")), policy()));
        assertEquals(Reason.MALFORMED, failure(withHeaders(msg, Map.of("Signature", "sig1=:AAAA:, sig9=:AAAA:", "Signature-Input", "sig9=(\"@method\");created=1")), policy()));
    }

    @Test
    void noSignatureAtAllIsMalformed() {
        assertEquals(Reason.MALFORMED, failure(unsigned(), policy()));
    }

    @Test
    void cavageLikeSignatureWithUnknownKeyIdFormatFails() {
        assertEquals(Reason.MALFORMED, failure(withHeaders(unsigned(), Map.of("Signature", "keyId=\"k1\"")), policy()));
    }
}
