package org.sitenetsoft.quarkus.httpsignatures.client;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.jboss.logging.Logger;
import org.sitenetsoft.httpsignatures.Headers;
import org.sitenetsoft.httpsignatures.Scheme;
import org.sitenetsoft.httpsignatures.SignedHeaders;

/**
 * Signs and sends {@code java.net.http} requests with double knocking: the preferred scheme first, and on 401 or
 * 403 once more with the other scheme, remembering per host which one worked.
 */
@ApplicationScoped
public class SigningHttpClient {

    private static final Logger LOG = Logger.getLogger("org.sitenetsoft.quarkus.httpsignatures");

    private final RequestSigner signer;

    @Inject
    public SigningHttpClient(RequestSigner signer) {
        this.signer = signer;
    }

    /**
     * @param body the request body bytes, or {@code null}; it replaces the request's own publisher so the digest
     *        and the bytes sent always agree
     */
    public HttpResponse<byte[]> send(HttpClient client, HttpRequest request, byte[] body, Optional<String> clientName)
            throws IOException, InterruptedException {
        URI target = request.uri();
        Scheme first = signer.schemeFor(target, clientName);
        HttpResponse<byte[]> response = client.send(signed(request, body, clientName, first), HttpResponse.BodyHandlers.ofByteArray());
        if (!rejected(response) || !signer.fallbackEnabled()) {
            return response;
        }
        Scheme second = first.other();
        LOG.debugf("%s rejected a %s signature (%d); retrying once with %s", target.getHost(), first.id(), response.statusCode(), second.id());
        HttpResponse<byte[]> retry = client.send(signed(request, body, clientName, second), HttpResponse.BodyHandlers.ofByteArray());
        if (!rejected(retry)) {
            signer.memory().remember(target.getHost(), second);
        }
        return retry;
    }

    public HttpRequest signed(HttpRequest request, byte[] body, Optional<String> clientName, Scheme scheme) {
        Map<String, List<String>> existing = new LinkedHashMap<>(request.headers().map());
        SignedHeaders headers = signer.sign(request.method(), request.uri(), Headers.of(existing), body, clientName, scheme);
        HttpRequest.Builder b = HttpRequest.newBuilder(request, (name, value) -> !headers.headers().containsKey(name));
        headers.applyTo(b::header);
        if (body != null) {
            b.method(request.method(), HttpRequest.BodyPublishers.ofByteArray(body));
        }
        return b.build();
    }

    static boolean rejected(HttpResponse<?> response) {
        return response.statusCode() == 401 || response.statusCode() == 403;
    }
}
