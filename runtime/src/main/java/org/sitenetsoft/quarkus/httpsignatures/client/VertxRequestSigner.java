package org.sitenetsoft.quarkus.httpsignatures.client;

import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.sitenetsoft.httpsignatures.Headers;
import org.sitenetsoft.httpsignatures.Scheme;
import org.sitenetsoft.httpsignatures.SignedHeaders;

import io.vertx.ext.web.client.HttpRequest;

/**
 * Signs a Vert.x Web Client request in place. The caller sends the same {@code body} bytes afterwards.
 */
@ApplicationScoped
public class VertxRequestSigner {

    private final RequestSigner signer;

    @Inject
    public VertxRequestSigner(RequestSigner signer) {
        this.signer = signer;
    }

    public <T> SignedHeaders sign(HttpRequest<T> request, URI target, byte[] body, Optional<String> clientName) {
        return sign(request, target, body, clientName, signer.schemeFor(target, clientName));
    }

    public <T> SignedHeaders sign(HttpRequest<T> request, URI target, byte[] body, Optional<String> clientName, Scheme scheme) {
        Map<String, List<String>> existing = new LinkedHashMap<>();
        for (Map.Entry<String, String> e : request.headers()) {
            existing.computeIfAbsent(e.getKey(), k -> new ArrayList<>()).add(e.getValue());
        }
        SignedHeaders headers = signer.sign(request.method().name(), target, Headers.of(existing), body, clientName, scheme);
        headers.applyTo(request::putHeader);
        return headers;
    }

    public RequestSigner requestSigner() {
        return signer;
    }
}
