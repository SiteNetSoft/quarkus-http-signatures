package org.sitenetsoft.httpsignatures;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

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

class CavageTest {

    static KeyPair rsa;
    static KeyPair ed;
    static final Instant NOW = Instant.parse("2026-10-24T12:00:00Z");
    static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    static final byte[] BODY = "{\"type\":\"Follow\"}".getBytes(StandardCharsets.UTF_8);

    @BeforeAll
    static void keys() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        rsa = g.generateKeyPair();
        ed = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    }

    static KeyResolver resolver() {
        return id -> switch (id) {
            case "https://alice.example/actor#main-key" -> Optional.of(new VerificationKey(id, Optional.empty(), rsa.getPublic()));
            case "ed" -> Optional.of(new VerificationKey(id, Optional.empty(), ed.getPublic()));
            default -> Optional.empty();
        };
    }

    static Map<String, List<String>> baseHeaders(Instant date) {
        Map<String, List<String>> h = new LinkedHashMap<>();
        h.put("Host", List.of("bob.example"));
        if (date != null) {
            h.put("Date", List.of(DateTimeFormatter.RFC_1123_DATE_TIME.format(date.atOffset(ZoneOffset.UTC))));
        }
        h.put("Content-Type", List.of("application/activity+json"));
        return h;
    }

    static HttpMessageView inbox(Map<String, List<String>> headers) {
        return HttpMessageView.of("POST", URI.create("https://bob.example/inbox"), Headers.of(headers), BODY);
    }

    static HttpMessageView signed(HttpMessageView msg, SignatureSpec spec, SigningKey key) {
        SignedHeaders signed = new HttpSigner().sign(msg, spec, key);
        Map<String, List<String>> h = new LinkedHashMap<>();
        msg.headers().names().forEach(n -> h.put(n, msg.headers().values(n)));
        signed.headers().forEach((k, v) -> h.put(k, List.of(v)));
        return HttpMessageView.of(msg.method(), msg.targetUri(), Headers.of(h), msg.body().map(BodyDigest::body).orElse(null));
    }

    @Test
    void signsAndVerifiesRsaSha256LikeMastodon() {
        String keyId = "https://alice.example/actor#main-key";
        SignatureSpec spec = SignatureSpec.cavage(keyId, Algorithm.RSA_SHA256, NOW, true);
        SignedHeaders headers = new HttpSigner().sign(inbox(baseHeaders(NOW)), spec, new SigningKey(keyId, Algorithm.RSA_SHA256, rsa.getPrivate()));
        String sig = headers.headers().get("Signature");
        assertTrue(sig.startsWith("keyId=\"" + keyId + "\",algorithm=\"rsa-sha256\",headers=\"(request-target) host date digest\",signature=\""), sig);
        assertEquals(Digests.legacyDigest(BODY), headers.headers().get("Digest"));

        HttpMessageView msg = signed(inbox(baseHeaders(NOW)), spec, new SigningKey(keyId, Algorithm.RSA_SHA256, rsa.getPrivate()));
        VerificationResult r = new HttpVerifier().verify(msg, VerificationPolicy.defaults(resolver()).withClock(CLOCK));
        assertEquals(Scheme.CAVAGE, r.scheme());
        assertEquals(keyId, r.keyId());
        assertEquals(Algorithm.RSA_SHA256, r.alg());
        assertEquals(List.of("(request-target)", "host", "date", "digest"), r.covered().stream().map(Component::name).toList());
    }

    @Test
    void addsDateWhenMessageHasNone() {
        SignedHeaders headers = new HttpSigner().sign(inbox(baseHeaders(null)),
                SignatureSpec.cavage("ed", Algorithm.ED25519, NOW, true), new SigningKey("ed", Algorithm.ED25519, ed.getPrivate()));
        assertEquals("Sat, 24 Oct 2026 12:00:00 GMT", headers.headers().get("Date"));
    }

    @Test
    void signatureBaseMatchesDraft12Example() {
        Map<String, List<String>> h = new LinkedHashMap<>();
        h.put("Host", List.of("example.com"));
        h.put("Date", List.of("Sun, 05 Jan 2014 21:31:40 GMT"));
        HttpMessageView msg = HttpMessageView.of("POST", URI.create("https://example.com/foo?param=value&pet=dog"), Headers.of(h), null);
        String base = SignatureBase.cavage(msg, List.of("(request-target)", "host", "date"), Optional.empty(), Optional.empty());
        assertEquals("(request-target): post /foo?param=value&pet=dog\nhost: example.com\ndate: Sun, 05 Jan 2014 21:31:40 GMT", base);
    }

    @Test
    void hs2019UsesKeyType() {
        SignatureSpec spec = SignatureSpec.cavage("ed", Algorithm.HS2019, NOW, true);
        HttpMessageView msg = signed(inbox(baseHeaders(NOW)), spec, new SigningKey("ed", Algorithm.HS2019, ed.getPrivate()));
        assertTrue(msg.headers().first("Signature").orElseThrow().contains("algorithm=\"hs2019\""));
        VerificationResult r = new HttpVerifier().verify(msg, VerificationPolicy.defaults(resolver()).withClock(CLOCK));
        assertEquals(Algorithm.ED25519, r.alg());
    }

    @Test
    void missingDateIsStale() {
        Map<String, List<String>> h = baseHeaders(null);
        SignatureSpec spec = SignatureSpec.cavage("ed", Algorithm.ED25519, NOW, true)
                .withCovered(List.of(Component.of("(request-target)"), Component.of("host"), Component.of("digest")));
        HttpMessageView msg = signed(inbox(h), spec, new SigningKey("ed", Algorithm.ED25519, ed.getPrivate()));
        // the signer adds Date; drop it again to simulate a sender that never sent one
        Map<String, List<String>> without = new LinkedHashMap<>();
        msg.headers().names().stream().filter(n -> !n.equalsIgnoreCase("Date")).forEach(n -> without.put(n, msg.headers().values(n)));
        HttpMessageView noDate = HttpMessageView.of("POST", msg.targetUri(), Headers.of(without), BODY);
        HttpSignatureException e = assertThrows(HttpSignatureException.class,
                () -> new HttpVerifier().verify(noDate, VerificationPolicy.defaults(resolver()).withClock(CLOCK).withStrictCoverage(false)));
        assertEquals(Reason.STALE, e.reason());
    }

    @Test
    void unparseableDateIsStale() {
        Map<String, List<String>> h = baseHeaders(null);
        h.put("Date", List.of("yesterday-ish"));
        HttpMessageView msg = signed(inbox(h), SignatureSpec.cavage("ed", Algorithm.ED25519, NOW, true), new SigningKey("ed", Algorithm.ED25519, ed.getPrivate()));
        HttpSignatureException e = assertThrows(HttpSignatureException.class,
                () -> new HttpVerifier().verify(msg, VerificationPolicy.defaults(resolver()).withClock(CLOCK)));
        assertEquals(Reason.STALE, e.reason());
    }

    @Test
    void oldDateIsStaleAndWithinMaxAgeIsFine() {
        Instant twoHoursAgo = NOW.minusSeconds(7200);
        HttpMessageView old = signed(inbox(baseHeaders(twoHoursAgo)), SignatureSpec.cavage("ed", Algorithm.ED25519, twoHoursAgo, true),
                new SigningKey("ed", Algorithm.ED25519, ed.getPrivate()));
        assertEquals(Reason.STALE, assertThrows(HttpSignatureException.class,
                () -> new HttpVerifier().verify(old, VerificationPolicy.defaults(resolver()).withClock(CLOCK))).reason());

        Instant tenMinutesAgo = NOW.minusSeconds(600);
        HttpMessageView recent = signed(inbox(baseHeaders(tenMinutesAgo)), SignatureSpec.cavage("ed", Algorithm.ED25519, tenMinutesAgo, true),
                new SigningKey("ed", Algorithm.ED25519, ed.getPrivate()));
        assertEquals(Scheme.CAVAGE, new HttpVerifier().verify(recent, VerificationPolicy.defaults(resolver()).withClock(CLOCK)).scheme());
    }

    @Test
    void missingRequiredCavageHeaderFails() {
        SignatureSpec spec = SignatureSpec.cavage("ed", Algorithm.ED25519, NOW, true)
                .withCovered(List.of(Component.of("(request-target)"), Component.of("date"), Component.of("digest")));
        HttpMessageView msg = signed(inbox(baseHeaders(NOW)), spec, new SigningKey("ed", Algorithm.ED25519, ed.getPrivate()));
        assertEquals(Reason.MISSING_COMPONENT, assertThrows(HttpSignatureException.class,
                () -> new HttpVerifier().verify(msg, VerificationPolicy.defaults(resolver()).withClock(CLOCK))).reason());
    }

    @Test
    void tamperedBodyFailsDigest() {
        HttpMessageView msg = signed(inbox(baseHeaders(NOW)), SignatureSpec.cavage("ed", Algorithm.ED25519, NOW, true),
                new SigningKey("ed", Algorithm.ED25519, ed.getPrivate()));
        HttpMessageView tampered = HttpMessageView.of("POST", msg.targetUri(), msg.headers(), "{\"type\":\"Delete\"}".getBytes(StandardCharsets.UTF_8));
        assertEquals(Reason.DIGEST_MISMATCH, assertThrows(HttpSignatureException.class,
                () -> new HttpVerifier().verify(tampered, VerificationPolicy.defaults(resolver()).withClock(CLOCK))).reason());
    }

    @Test
    void parsesMastodonStyleHeader() {
        CavageSignature.Parsed p = CavageSignature.parse(
                "keyId=\"https://mastodon.example/users/alice#main-key\",algorithm=\"rsa-sha256\",headers=\"(request-target) host date digest content-type\",signature=\"AAAA\"");
        assertEquals("https://mastodon.example/users/alice#main-key", p.keyId());
        assertEquals(Optional.of("rsa-sha256"), p.algorithm());
        assertEquals(List.of("(request-target)", "host", "date", "digest", "content-type"), p.headers());
        assertEquals(3, p.signature().length);
    }
}
