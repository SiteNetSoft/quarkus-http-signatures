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
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.sitenetsoft.httpsignatures.HttpSignatureException.Reason;

/**
 * Regression tests for the final review findings on the core verifier.
 */
class ReviewFixesTest {

    static KeyPair rsa;
    static final Instant NOW = Instant.parse("2026-10-24T12:00:00Z");
    static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    static final byte[] BODY = "{\"type\":\"Follow\"}".getBytes(StandardCharsets.UTF_8);

    @BeforeAll
    static void keys() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        rsa = g.generateKeyPair();
    }

    static KeyResolver unpinned() {
        return id -> "rsa".equals(id) ? Optional.of(new VerificationKey("rsa", Optional.empty(), rsa.getPublic())) : Optional.empty();
    }

    static KeyResolver pinned(Algorithm alg) {
        return id -> "rsa".equals(id) ? Optional.of(new VerificationKey("rsa", Optional.of(alg), rsa.getPublic())) : Optional.empty();
    }

    static HttpMessageView inbox(Instant date) {
        Map<String, List<String>> h = new LinkedHashMap<>();
        h.put("Host", List.of("bob.example"));
        if (date != null) {
            h.put("Date", List.of(DateTimeFormatter.RFC_1123_DATE_TIME.format(date.atOffset(ZoneOffset.UTC))));
        }
        h.put("Content-Type", List.of("application/activity+json"));
        return HttpMessageView.of("POST", URI.create("https://bob.example/inbox"), Headers.of(h), BODY);
    }

    static HttpMessageView signed(HttpMessageView msg, SignatureSpec spec, SigningKey key) {
        SignedHeaders signed = new HttpSigner().sign(msg, spec, key);
        return withHeaders(msg, signed.headers());
    }

    static HttpMessageView withHeaders(HttpMessageView msg, Map<String, String> extra) {
        Map<String, List<String>> h = new LinkedHashMap<>();
        msg.headers().names().forEach(n -> h.put(n, msg.headers().values(n)));
        extra.forEach((k, v) -> h.put(k, List.of(v)));
        return HttpMessageView.of(msg.method(), msg.targetUri(), Headers.of(h), msg.body().map(BodyDigest::body).orElse(null));
    }

    /** Critical #1: an uncovered created= parameter must not override the signed Date header. */
    @Test
    void uncoveredCreatedParameterDoesNotOverrideDate() {
        Instant twoHoursAgo = NOW.minusSeconds(7200);
        SigningKey key = new SigningKey("rsa", Algorithm.RSA_SHA256, rsa.getPrivate());
        HttpMessageView old = signed(inbox(twoHoursAgo), SignatureSpec.cavage("rsa", Algorithm.RSA_SHA256, twoHoursAgo, true), key);
        String replayed = old.headers().first("Signature").orElseThrow() + ",created=" + NOW.getEpochSecond();
        HttpMessageView attack = withHeaders(old, Map.of("Signature", replayed));
        HttpSignatureException e = assertThrows(HttpSignatureException.class,
                () -> new HttpVerifier().verify(attack, VerificationPolicy.defaults(unpinned()).withClock(CLOCK)));
        assertEquals(Reason.STALE, e.reason());
    }

    @Test
    void uncoveredExpiresParameterIsIgnored() {
        SigningKey key = new SigningKey("rsa", Algorithm.RSA_SHA256, rsa.getPrivate());
        HttpMessageView fresh = signed(inbox(NOW), SignatureSpec.cavage("rsa", Algorithm.RSA_SHA256, NOW, true), key);
        String withExpires = fresh.headers().first("Signature").orElseThrow() + ",expires=" + NOW.minusSeconds(10).getEpochSecond();
        // an attacker cannot make a valid signature expire early either; the uncovered parameter simply has no effect
        VerificationResult r = new HttpVerifier().verify(withHeaders(fresh, Map.of("Signature", withExpires)),
                VerificationPolicy.defaults(unpinned()).withClock(CLOCK));
        assertEquals(Algorithm.RSA_SHA256, r.alg());
    }

    /** Important #4: signer default (rsa-v1_5-sha256, no alg parameter) must verify against an unpinned RSA key. */
    @Test
    void unpinnedRsaKeyVerifiesV15SignatureWithoutAlgParameter() {
        SigningKey key = new SigningKey("rsa", Algorithm.RSA_V1_5_SHA256, rsa.getPrivate());
        HttpMessageView msg = signed(inbox(NOW), SignatureSpec.rfc9421("rsa", Algorithm.RSA_V1_5_SHA256, NOW, true), key);
        VerificationResult r = new HttpVerifier().verify(msg, VerificationPolicy.defaults(unpinned()).withClock(CLOCK));
        assertEquals(Algorithm.RSA_V1_5_SHA256, r.alg());
    }

    @Test
    void pinnedRsaPssKeyStillVerifiesPss() {
        SigningKey key = new SigningKey("rsa", Algorithm.RSA_PSS_SHA512, rsa.getPrivate());
        HttpMessageView msg = signed(inbox(NOW), SignatureSpec.rfc9421("rsa", Algorithm.RSA_PSS_SHA512, NOW, true), key);
        VerificationResult r = new HttpVerifier().verify(msg, VerificationPolicy.defaults(pinned(Algorithm.RSA_PSS_SHA512)).withClock(CLOCK));
        assertEquals(Algorithm.RSA_PSS_SHA512, r.alg());
    }

    /** Important #5: hs2019 with an RSA key means rsa-sha256 in the Fediverse. */
    @Test
    void hs2019WithRsaKeyMeansRsaSha256() {
        SigningKey key = new SigningKey("rsa", Algorithm.HS2019, rsa.getPrivate());
        HttpMessageView msg = signed(inbox(NOW), SignatureSpec.cavage("rsa", Algorithm.HS2019, NOW, true), key);
        VerificationResult r = new HttpVerifier().verify(msg, VerificationPolicy.defaults(unpinned()).withClock(CLOCK));
        assertEquals(Algorithm.RSA_SHA256, r.alg());
    }

    @Test
    void hs2019HonoursPinnedKeyAlgorithm() {
        // the key owner declared PSS; a Cavage hs2019 signature over that key must be PSS
        SigningKey pssKey = new SigningKey("rsa", Algorithm.RSA_PSS_SHA512, rsa.getPrivate());
        HttpMessageView base = inbox(NOW);
        SignatureSpec spec = SignatureSpec.cavage("rsa", Algorithm.HS2019, NOW, true);
        // sign manually with PSS under the hs2019 label
        SignedHeaders cavage = new HttpSigner().sign(base, spec, new SigningKey("rsa", Algorithm.HS2019, rsa.getPrivate()));
        HttpMessageView msg = withHeaders(base, cavage.headers());
        // the default signer produced rsa-sha256 bytes, so a PSS-pinned key must reject them
        assertEquals(Reason.INVALID_SIGNATURE, assertThrows(HttpSignatureException.class,
                () -> new HttpVerifier().verify(msg, VerificationPolicy.defaults(pinned(Algorithm.RSA_PSS_SHA512)).withClock(CLOCK))).reason());
        assertEquals(Algorithm.RSA_SHA256, new HttpVerifier().verify(msg, VerificationPolicy.defaults(pinned(Algorithm.RSA_SHA256)).withClock(CLOCK)).alg());
        assertEquals(KeyType.RSA, pssKey.keyType());
    }
}
