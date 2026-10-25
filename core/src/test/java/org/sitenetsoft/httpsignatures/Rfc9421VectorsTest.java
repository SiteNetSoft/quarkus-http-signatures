package org.sitenetsoft.httpsignatures;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.sitenetsoft.httpsignatures.Rfc9421Vectors.*;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

class Rfc9421VectorsTest {

    static Stream<Rfc9421Vectors.Vector> requestVectors() {
        return Stream.of(B21, B22, B23, B25, B26);
    }

    @ParameterizedTest
    @MethodSource("requestVectors")
    void verifiesPublishedRequestSignature(Rfc9421Vectors.Vector v) {
        VerificationResult r = new HttpVerifier().verify(request(v), relaxedPolicy());
        assertEquals(Scheme.RFC9421, r.scheme());
        assertEquals(Instant.ofEpochSecond(CREATED), r.created());
    }

    @Test
    void verifiesPublishedResponseSignature() {
        VerificationResult r = new HttpVerifier().verify(response(B24), relaxedPolicy());
        assertEquals("test-key-ecc-p256", r.keyId());
        assertEquals(Algorithm.ECDSA_P256_SHA256, r.alg());
    }

    @Test
    void signatureBaseMatchesB23() {
        String expected = """
                "date": Tue, 20 Apr 2021 02:07:55 GMT
                "@method": POST
                "@path": /foo
                "@query": ?param=Value&Pet=dog
                "@authority": example.com
                "content-type": application/json
                "content-digest": sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:
                "content-length": 18
                "@signature-params": ("date" "@method" "@path" "@query" "@authority" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-rsa-pss\"""";
        assertEquals(expected, HttpVerifier.signatureBase(request(B23)).orElseThrow());
    }

    @Test
    void signatureBaseMatchesB22QueryParam() {
        String base = HttpVerifier.signatureBase(request(B22)).orElseThrow();
        assertTrue(base.startsWith("\"@authority\": example.com\n\"content-digest\": sha-512=:"), base);
        assertTrue(base.contains("\n\"@query-param\";name=\"Pet\": dog\n"), base);
    }

    @Test
    void hmacVectorSignsByteForByte() {
        SignatureSpec spec = new SignatureSpec(Scheme.RFC9421, "test-shared-secret", Algorithm.HMAC_SHA256,
                List.of(Component.of("date"), Component.of("@authority"), Component.of("content-type")),
                Instant.ofEpochSecond(CREATED), Optional.empty(), Optional.empty(), Optional.empty());
        SignedHeaders signed = new HttpSigner().sign(request(null), spec,
                new SigningKey("test-shared-secret", Algorithm.HMAC_SHA256, sharedSecret()), "sig-b25");
        assertEquals(B25.signatureInput(), signed.headers().get("Signature-Input"));
        assertEquals(B25.signature(), signed.headers().get("Signature"));
    }

    @Test
    void ed25519VectorSignsByteForByte() {
        SignatureSpec spec = new SignatureSpec(Scheme.RFC9421, "test-key-ed25519", Algorithm.ED25519,
                Stream.of("date", "@method", "@path", "@authority", "content-type", "content-length").map(Component::of).toList(),
                Instant.ofEpochSecond(CREATED), Optional.empty(), Optional.empty(), Optional.empty());
        SignedHeaders signed = new HttpSigner().sign(request(null), spec,
                new SigningKey("test-key-ed25519", Algorithm.ED25519, privateKey("test-key-ed25519.pem")), "sig-b26");
        assertEquals(B26.signatureInput(), signed.headers().get("Signature-Input"));
        assertEquals(B26.signature(), signed.headers().get("Signature"));
    }

    @Test
    void rsaPssSignatureVerifiesWithOurOwnSigner() {
        SignatureSpec spec = SignatureSpec.rfc9421("test-key-rsa-pss", Algorithm.RSA_PSS_SHA512, Instant.ofEpochSecond(CREATED), true)
                .withTag("header-example").withNonce("abc123");
        HttpMessageView unsigned = request(null);
        SignedHeaders signed = new HttpSigner().sign(unsigned, spec,
                new SigningKey("test-key-rsa-pss", Algorithm.RSA_PSS_SHA512, privateKey("test-key-rsa-pss.pem")));
        Map<String, List<String>> h = requestHeaders();
        signed.headers().forEach((k, val) -> h.put(k, List.of(val)));
        HttpMessageView msg = HttpMessageView.of("POST", unsigned.targetUri(), Headers.of(h), REQUEST_BODY);
        VerificationResult r = new HttpVerifier().verify(msg, VerificationPolicy.defaults(resolver()).withClock(CLOCK));
        assertEquals(Algorithm.RSA_PSS_SHA512, r.alg());
        assertTrue(r.covered().contains(Component.of("content-digest")));
        assertArrayEquals(REQUEST_BODY, unsigned.body().orElseThrow().body());
    }

    @Test
    void defaultSpecAddsContentDigestHeaderWhenMissing() {
        Map<String, List<String>> h = requestHeaders();
        h.remove("Content-Digest");
        HttpMessageView msg = HttpMessageView.of("POST", request(null).targetUri(), Headers.of(h), REQUEST_BODY);
        SignedHeaders signed = new HttpSigner().sign(msg,
                SignatureSpec.rfc9421("test-key-ed25519", Algorithm.ED25519, Instant.ofEpochSecond(CREATED), true),
                new SigningKey("test-key-ed25519", Algorithm.ED25519, privateKey("test-key-ed25519.pem")));
        assertEquals("sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:", signed.headers().get("Content-Digest"));
    }
}
