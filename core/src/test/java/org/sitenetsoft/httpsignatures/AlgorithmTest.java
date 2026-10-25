package org.sitenetsoft.httpsignatures;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Optional;

import org.junit.jupiter.api.Test;

class AlgorithmTest {

    @Test
    void everySpecIdResolves() {
        for (String id : new String[] { "rsa-v1_5-sha256", "rsa-pss-sha512", "ecdsa-p256-sha256", "ecdsa-p384-sha384",
                "ed25519", "hmac-sha256", "rsa-sha256", "hs2019" }) {
            assertTrue(Algorithm.fromId(id).isPresent(), id);
            assertEquals(id, Algorithm.fromId(id).get().id());
        }
        assertEquals(Optional.empty(), Algorithm.fromId("md5"));
    }

    @Test
    void schemeMembership() {
        assertTrue(Algorithm.ED25519.isRfc9421());
        assertTrue(Algorithm.ED25519.isCavage());
        assertTrue(Algorithm.RSA_SHA256.isCavage());
        assertFalse(Algorithm.RSA_SHA256.isRfc9421());
        assertTrue(Algorithm.RSA_PSS_SHA512.isRfc9421());
        assertFalse(Algorithm.RSA_PSS_SHA512.isCavage());
    }

    @Test
    void keyTypes() {
        assertEquals(KeyType.RSA, Algorithm.RSA_V1_5_SHA256.keyType());
        assertEquals(KeyType.EC_P384, Algorithm.ECDSA_P384_SHA384.keyType());
        assertEquals(KeyType.HMAC, Algorithm.HMAC_SHA256.keyType());
        assertEquals(null, Algorithm.HS2019.keyType());
    }

    @Test
    void componentNamesAreLowercasedAndDerivedDetected() {
        assertEquals("content-digest", Component.of("Content-Digest").name());
        assertTrue(Component.of("@method").isDerived());
        assertFalse(Component.of("date").isDerived());
        assertEquals("\"@query-param\";name=\"Pet\"", Component.of("@query-param").withParam("name", "Pet").serialized());
    }

    @Test
    void headersCombineValuesPerRfc9421() {
        Headers h = Headers.of(java.util.Map.of("Example-Header", java.util.List.of("  value, with   spaces  ", "second")));
        assertEquals("value, with spaces, second", h.combined("example-header"));
        assertEquals(Optional.of("  value, with   spaces  "), h.first("EXAMPLE-HEADER"));
        assertEquals(Optional.empty(), h.first("missing"));
    }
}
