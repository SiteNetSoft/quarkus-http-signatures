package org.sitenetsoft.httpsignatures;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * What to sign and how.
 */
public record SignatureSpec(Scheme scheme, String keyId, Algorithm alg, List<Component> covered, Instant created,
        Optional<Instant> expires, Optional<String> nonce, Optional<String> tag) {

    public SignatureSpec {
        if (scheme == null || keyId == null || alg == null || created == null) {
            throw new IllegalArgumentException("scheme, keyId, alg and created are required");
        }
        covered = List.copyOf(covered);
        expires = expires == null ? Optional.empty() : expires;
        nonce = nonce == null ? Optional.empty() : nonce;
        tag = tag == null ? Optional.empty() : tag;
    }

    /**
     * RFC 9421 with the mandatory coverage: {@code @method}, {@code @target-uri} and, with a body,
     * {@code content-digest}.
     */
    public static SignatureSpec rfc9421(String keyId, Algorithm alg, Instant created, boolean hasBody) {
        List<Component> covered = new ArrayList<>(List.of(Component.of("@method"), Component.of("@target-uri")));
        if (hasBody) {
            covered.add(Component.of("content-digest"));
        }
        return new SignatureSpec(Scheme.RFC9421, keyId, alg, covered, created, Optional.empty(), Optional.empty(), Optional.empty());
    }

    /**
     * Cavage with the mandatory coverage: {@code (request-target)}, {@code host}, {@code date} and, with a body,
     * {@code digest}.
     */
    public static SignatureSpec cavage(String keyId, Algorithm alg, Instant created, boolean hasBody) {
        List<Component> covered = new ArrayList<>(List.of(Component.of("(request-target)"), Component.of("host"), Component.of("date")));
        if (hasBody) {
            covered.add(Component.of("digest"));
        }
        return new SignatureSpec(Scheme.CAVAGE, keyId, alg, covered, created, Optional.empty(), Optional.empty(), Optional.empty());
    }

    public SignatureSpec withCovered(List<Component> covered) {
        return new SignatureSpec(scheme, keyId, alg, covered, created, expires, nonce, tag);
    }

    public SignatureSpec withExpires(Instant expires) {
        return new SignatureSpec(scheme, keyId, alg, covered, created, Optional.ofNullable(expires), nonce, tag);
    }

    public SignatureSpec withNonce(String nonce) {
        return new SignatureSpec(scheme, keyId, alg, covered, created, expires, Optional.ofNullable(nonce), tag);
    }

    public SignatureSpec withTag(String tag) {
        return new SignatureSpec(scheme, keyId, alg, covered, created, expires, nonce, Optional.ofNullable(tag));
    }

    public boolean covers(String componentName) {
        return covered.stream().anyMatch(c -> c.name().equals(componentName));
    }
}
