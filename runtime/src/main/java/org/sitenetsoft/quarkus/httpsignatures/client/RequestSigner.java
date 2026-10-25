package org.sitenetsoft.quarkus.httpsignatures.client;

import java.net.URI;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.sitenetsoft.httpsignatures.Algorithm;
import org.sitenetsoft.httpsignatures.Component;
import org.sitenetsoft.httpsignatures.Headers;
import org.sitenetsoft.httpsignatures.HttpMessageView;
import org.sitenetsoft.httpsignatures.HttpSigner;
import org.sitenetsoft.httpsignatures.KeyType;
import org.sitenetsoft.httpsignatures.Scheme;
import org.sitenetsoft.httpsignatures.SignatureSpec;
import org.sitenetsoft.httpsignatures.SignedHeaders;
import org.sitenetsoft.httpsignatures.SigningKey;
import org.sitenetsoft.quarkus.httpsignatures.HttpSignaturesConfig;
import org.sitenetsoft.quarkus.httpsignatures.ReactiveSigningKeyProvider;
import org.sitenetsoft.quarkus.httpsignatures.SigningKeyProvider;

import io.quarkus.arc.All;

/**
 * Picks the key and scheme for an outbound request and produces the headers to add. Shared by every client
 * integration.
 */
@ApplicationScoped
public class RequestSigner {

    private final HttpSignaturesConfig config;
    private final List<SigningKeyProvider> providers;
    private final List<ReactiveSigningKeyProvider> reactiveProviders;
    private final SchemeMemory memory;
    private final HttpSigner signer = new HttpSigner();

    @Inject
    public RequestSigner(HttpSignaturesConfig config, @All List<SigningKeyProvider> providers,
            @All List<ReactiveSigningKeyProvider> reactiveProviders, SchemeMemory memory) {
        this.config = config;
        this.providers = providers;
        this.reactiveProviders = reactiveProviders;
        this.memory = memory;
    }

    /**
     * The scheme to try first for a host: what the host accepted before, else the client's or the global preference.
     */
    public Scheme schemeFor(URI target, Optional<String> clientName) {
        Optional<Scheme> remembered = memory.preferredFor(target.getHost());
        if (remembered.isPresent()) {
            return remembered.get();
        }
        return clientName.map(config.clients()::get).flatMap(c -> c == null ? Optional.empty() : c.scheme())
                .orElse(config.sign().preferredScheme());
    }

    public boolean fallbackEnabled() {
        return config.sign().fallback();
    }

    public SchemeMemory memory() {
        return memory;
    }

    public SigningKey keyFor(URI target, Optional<String> clientName) {
        for (SigningKeyProvider p : providers) {
            Optional<SigningKey> k = p.select(target, clientName);
            if (k.isPresent()) {
                return k.get();
            }
        }
        for (ReactiveSigningKeyProvider p : reactiveProviders) {
            Optional<SigningKey> k = p.select(target, clientName).await().atMost(java.time.Duration.ofSeconds(30));
            if (k.isPresent()) {
                return k.get();
            }
        }
        throw new IllegalStateException("No signing key for " + target.getHost()
                + (clientName.map(c -> " (client '" + c + "')").orElse("")) + ": configure quarkus.http-signatures.keys.\"<id>\".location"
                + " or provide a SigningKeyProvider bean");
    }

    /**
     * Signs with the scheme {@link #schemeFor} chooses.
     */
    public SignedHeaders sign(String method, URI target, Headers existing, byte[] body, Optional<String> clientName) {
        return sign(method, target, existing, body, clientName, schemeFor(target, clientName));
    }

    public SignedHeaders sign(String method, URI target, Headers existing, byte[] body, Optional<String> clientName, Scheme scheme) {
        SigningKey key = keyFor(target, clientName);
        Algorithm alg = algorithmFor(key, scheme);
        SigningKey schemeKey = alg == key.algorithm() ? key : new SigningKey(key.keyId(), alg, key.key());
        boolean hasBody = body != null && body.length > 0;
        SignatureSpec spec = scheme == Scheme.RFC9421
                ? SignatureSpec.rfc9421(key.keyId(), alg, Instant.now(), hasBody)
                : SignatureSpec.cavage(key.keyId(), alg, Instant.now(), hasBody);
        Optional<List<String>> components = clientName.map(config.clients()::get).flatMap(c -> c == null ? Optional.empty() : c.components());
        if (components.isPresent()) {
            spec = spec.withCovered(components.get().stream().map(Component::of).toList());
        }
        HttpMessageView msg = HttpMessageView.of(method, target, withHost(existing, target), body);
        return signer.sign(msg, spec, schemeKey);
    }

    /**
     * Adapts a key's configured algorithm to the scheme: the same key signs {@code rsa-v1_5-sha256} under RFC 9421
     * and {@code rsa-sha256} under Cavage; non-RSA keys use {@code hs2019} under Cavage.
     */
    public static Algorithm algorithmFor(SigningKey key, Scheme scheme) {
        Algorithm a = key.algorithm();
        KeyType type = key.keyType();
        if (scheme == Scheme.RFC9421) {
            if (a.isRfc9421()) {
                return a;
            }
            return switch (type) {
                case RSA -> Algorithm.RSA_V1_5_SHA256;
                case EC_P256 -> Algorithm.ECDSA_P256_SHA256;
                case EC_P384 -> Algorithm.ECDSA_P384_SHA384;
                case ED25519 -> Algorithm.ED25519;
                case HMAC -> Algorithm.HMAC_SHA256;
            };
        }
        if (a.isCavage()) {
            return a;
        }
        return type == KeyType.RSA ? Algorithm.RSA_SHA256 : Algorithm.HS2019;
    }

    static Headers withHost(Headers existing, URI target) {
        if (existing != null && existing.contains("Host")) {
            return existing;
        }
        Map<String, List<String>> all = new LinkedHashMap<>();
        if (existing != null) {
            for (String n : existing.names()) {
                all.put(n, existing.values(n));
            }
        }
        String host = target.getHost() + (target.getPort() == -1 ? "" : ":" + target.getPort());
        all.put("Host", List.of(host));
        return Headers.of(all);
    }
}
