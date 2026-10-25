package org.sitenetsoft.httpsignatures;

import java.net.URI;
import java.util.Optional;
import java.util.OptionalInt;

/**
 * A framework-neutral view of an HTTP message. Adapters exist for Vert.x, JAX-RS and {@code java.net.http}.
 */
public interface HttpMessageView {

    /**
     * The request method; empty for a response.
     */
    String method();

    /**
     * The full target URI of a request; {@code null} for a response.
     */
    URI targetUri();

    Headers headers();

    /**
     * The body, when the message has one and it is available for digest checks.
     */
    Optional<BodyDigest> body();

    /**
     * The status code of a response; empty for a request.
     */
    default OptionalInt status() {
        return OptionalInt.empty();
    }

    default boolean isRequest() {
        return status().isEmpty();
    }

    static HttpMessageView of(String method, URI targetUri, Headers headers, byte[] body) {
        return new SimpleHttpMessage(method, targetUri, headers, bodyOf(body), OptionalInt.empty());
    }

    static HttpMessageView response(int status, Headers headers, byte[] body) {
        return new SimpleHttpMessage("", null, headers, bodyOf(body), OptionalInt.of(status));
    }

    private static Optional<BodyDigest> bodyOf(byte[] body) {
        return body == null || body.length == 0 ? Optional.empty() : Optional.of(BodyDigest.of(body));
    }
}
