package org.sitenetsoft.quarkus.httpsignatures.vertx;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class RequestVerifierBodyTest {

    @Test
    void bodyCapableMethodsAreReadEvenWithoutLengthHeaders() {
        // HTTP/2 requests carry neither Content-Length nor Transfer-Encoding; the body must still be digest-checked
        assertTrue(RequestVerifier.shouldReadBody("POST", null, null));
        assertTrue(RequestVerifier.shouldReadBody("PUT", null, null));
        assertTrue(RequestVerifier.shouldReadBody("PATCH", null, null));
    }

    @Test
    void getWithoutBodyHeadersIsNotRead() {
        assertFalse(RequestVerifier.shouldReadBody("GET", null, null));
        assertFalse(RequestVerifier.shouldReadBody("HEAD", null, null));
        assertFalse(RequestVerifier.shouldReadBody("POST", "0", null));
    }

    @Test
    void explicitBodyHeadersAlwaysRead() {
        assertTrue(RequestVerifier.shouldReadBody("GET", "12", null));
        assertTrue(RequestVerifier.shouldReadBody("DELETE", null, "chunked"));
    }
}
