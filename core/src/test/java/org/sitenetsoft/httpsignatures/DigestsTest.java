package org.sitenetsoft.httpsignatures;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

class DigestsTest {

    static final byte[] BODY = "{\"hello\": \"world\"}".getBytes(StandardCharsets.UTF_8);
    static final String RFC9530_SHA256 = "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:";

    @Test
    void contentDigestSha256OfRfc9530Example() {
        assertEquals(RFC9530_SHA256, Digests.contentDigest(BODY, DigestAlgorithm.SHA_256));
    }

    @Test
    void contentDigestSha512RoundTrips() {
        String header = Digests.contentDigest(BODY, DigestAlgorithm.SHA_512);
        assertTrue(header.startsWith("sha-512=:"));
        assertTrue(Digests.verifyContentDigest(header, BODY));
    }

    @Test
    void verifyAcceptsMatchingAndRejectsTampered() {
        assertTrue(Digests.verifyContentDigest(RFC9530_SHA256, BODY));
        assertFalse(Digests.verifyContentDigest(RFC9530_SHA256, "{\"hello\": \"World\"}".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void verifyRequiresEveryKnownAlgorithmToMatch() {
        String good512 = Digests.contentDigest(BODY, DigestAlgorithm.SHA_512);
        assertTrue(Digests.verifyContentDigest(RFC9530_SHA256 + ", " + good512, BODY));
        assertFalse(Digests.verifyContentDigest(RFC9530_SHA256 + ", sha-512=:AAAA:", BODY));
    }

    @Test
    void verifyRejectsUnknownOnlyAlgorithms() {
        assertFalse(Digests.verifyContentDigest("md5=:AAAA:", BODY));
        assertFalse(Digests.verifyContentDigest("", BODY));
    }

    @Test
    void legacyDigestRoundTrip() {
        String header = Digests.legacyDigest(BODY);
        assertEquals("SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=", header);
        assertTrue(Digests.verifyLegacyDigest(header, BODY));
        assertTrue(Digests.verifyLegacyDigest("sha-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=", BODY));
        assertFalse(Digests.verifyLegacyDigest("SHA-256=AAAA", BODY));
        assertFalse(Digests.verifyLegacyDigest("MD5=AAAA", BODY));
    }
}
