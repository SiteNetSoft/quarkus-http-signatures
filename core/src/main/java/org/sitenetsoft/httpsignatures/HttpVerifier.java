package org.sitenetsoft.httpsignatures;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.sitenetsoft.httpsignatures.HttpSignatureException.Reason;
import org.sitenetsoft.httpsignatures.StructuredFields.InnerList;
import org.sitenetsoft.httpsignatures.StructuredFields.Item;

/**
 * Verifies either scheme, picked from the headers: {@code Signature-Input} means RFC 9421, a lone {@code Signature}
 * means Cavage. Every failure is an {@link HttpSignatureException} with a reason; nothing else escapes.
 */
public final class HttpVerifier implements Verifier {

    @Override
    public VerificationResult verify(HttpMessageView msg, VerificationPolicy policy) {
        try {
            Scheme scheme = detect(msg);
            if (!policy.schemes().contains(scheme)) {
                throw new HttpSignatureException(Reason.SCHEME_NOT_ALLOWED, "Scheme " + scheme.id() + " is not accepted");
            }
            return scheme == Scheme.RFC9421 ? verifyRfc9421(msg, policy) : verifyCavage(msg, policy);
        } catch (HttpSignatureException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new HttpSignatureException(Reason.MALFORMED, "Unreadable signature: " + e.getClass().getSimpleName(), e);
        }
    }

    public static Scheme detect(HttpMessageView msg) {
        if (msg.headers().contains("Signature-Input")) {
            return Scheme.RFC9421;
        }
        if (msg.headers().contains("Signature")) {
            return Scheme.CAVAGE;
        }
        throw new HttpSignatureException(Reason.MALFORMED, "No Signature header");
    }

    /**
     * The signature base a verifier would compute for this message, for diagnostics. Never log it in production
     * next to a signature value.
     */
    public static Optional<String> signatureBase(HttpMessageView msg) {
        try {
            if (detect(msg) == Scheme.RFC9421) {
                Rfc9421Headers h = Rfc9421Headers.parse(msg);
                return Optional.of(SignatureBase.rfc9421(msg, h.covered, h.serializedParams));
            }
            CavageSignature.Parsed p = CavageSignature.parse(msg.headers().combined("Signature"));
            return Optional.of(SignatureBase.cavage(msg, p.headers(), p.created(), p.expires()));
        } catch (RuntimeException e) {
            return Optional.empty();
        }
    }

    // ---- RFC 9421

    private record Rfc9421Headers(String label, InnerList inner, List<Component> covered, String serializedParams, byte[] signature) {

        static Rfc9421Headers parse(HttpMessageView msg) {
            Map<String, Object> inputs = StructuredFields.parseDictionary(msg.headers().combined("Signature-Input"));
            Map<String, Object> sigs = StructuredFields.parseDictionary(msg.headers().combined("Signature"));
            for (Map.Entry<String, Object> e : inputs.entrySet()) {
                Object sig = sigs.get(e.getKey());
                if (sig instanceof Item item && item.value() instanceof byte[] bytes && e.getValue() instanceof InnerList inner) {
                    List<Component> covered = new ArrayList<>();
                    for (Item i : inner.items()) {
                        if (!(i.value() instanceof String name)) {
                            throw new HttpSignatureException(Reason.MALFORMED, "Covered component is not a string");
                        }
                        Map<String, String> params = new java.util.LinkedHashMap<>();
                        i.params().forEach((k, v) -> params.put(k, v instanceof String s ? s : String.valueOf(v)));
                        covered.add(new Component(name, params));
                    }
                    return new Rfc9421Headers(e.getKey(), inner, covered, StructuredFields.serializeInnerList(inner), bytes);
                }
            }
            throw new HttpSignatureException(Reason.MALFORMED, "No label present in both Signature-Input and Signature");
        }
    }

    private VerificationResult verifyRfc9421(HttpMessageView msg, VerificationPolicy policy) {
        Rfc9421Headers h = Rfc9421Headers.parse(msg);
        Map<String, Object> params = h.inner.params();
        String keyId = params.get("keyid") instanceof String s ? s : null;
        if (keyId == null) {
            throw new HttpSignatureException(Reason.MALFORMED, "Signature-Input has no keyid");
        }
        VerificationKey key = policy.keys().resolve(keyId)
                .orElseThrow(() -> new HttpSignatureException(Reason.UNKNOWN_KEY, "Unknown key id"));
        KeyType keyType = key.keyType();

        Algorithm alg;
        Object declared = params.get("alg");
        if (declared != null) {
            alg = Algorithm.fromId(String.valueOf(declared)).filter(Algorithm::isRfc9421).orElseThrow(
                    () -> new HttpSignatureException(Reason.UNSUPPORTED_ALGORITHM, "Unsupported algorithm " + declared));
            if (key.algorithm().isPresent() && key.algorithm().get() != alg) {
                throw new HttpSignatureException(Reason.ALGORITHM_KEY_MISMATCH, "Declared algorithm does not match the key's");
            }
        } else {
            alg = key.algorithm().orElseGet(() -> defaultRfc9421(keyType));
        }
        if (alg.keyType() != keyType) {
            throw new HttpSignatureException(Reason.ALGORITHM_KEY_MISMATCH, "Algorithm " + alg.id() + " does not match key type " + keyType);
        }

        if (policy.strictCoverage()) {
            boolean hasMethod = covers(h.covered, "@method");
            boolean hasTarget = covers(h.covered, "@target-uri") || (covers(h.covered, "@authority") && covers(h.covered, "@path"));
            if (msg.isRequest() && (!hasMethod || !hasTarget)) {
                throw new HttpSignatureException(Reason.MISSING_COMPONENT, "Signature must cover @method and @target-uri (or @authority and @path)");
            }
            if (!msg.isRequest() && !covers(h.covered, "@status")) {
                throw new HttpSignatureException(Reason.MISSING_COMPONENT, "Response signature must cover @status");
            }
            if (hasBody(msg) && !covers(h.covered, "content-digest")) {
                throw new HttpSignatureException(Reason.MISSING_COMPONENT, "Signature over a body must cover content-digest");
            }
        }
        requireComponents(h.covered, policy);
        checkDigest(msg, policy, "Content-Digest", null);

        Instant created = params.get("created") instanceof Long c ? Instant.ofEpochSecond(c) : null;
        Optional<Instant> expires = params.get("expires") instanceof Long e ? Optional.of(Instant.ofEpochSecond(e)) : Optional.empty();
        checkTime(created, expires, policy);
        checkNonce(params.get("nonce") instanceof String n ? n : null, expires, created, policy);

        String base = SignatureBase.rfc9421(msg, h.covered, h.serializedParams);
        if (!Jca.verify(alg, Scheme.RFC9421, key.key(), base.getBytes(StandardCharsets.UTF_8), h.signature)) {
            throw new HttpSignatureException(Reason.INVALID_SIGNATURE, "Signature does not verify");
        }
        return new VerificationResult(Scheme.RFC9421, keyId, alg, h.covered, created, key);
    }

    /**
     * The algorithm assumed for an unpinned key when {@code Signature-Input} carries no {@code alg}. RSA defaults to
     * {@code rsa-v1_5-sha256}, matching what this library signs with by default and what the Fediverse uses.
     */
    static Algorithm defaultRfc9421(KeyType type) {
        return switch (type) {
            case RSA -> Algorithm.RSA_V1_5_SHA256;
            case EC_P256 -> Algorithm.ECDSA_P256_SHA256;
            case EC_P384 -> Algorithm.ECDSA_P384_SHA384;
            case ED25519 -> Algorithm.ED25519;
            case HMAC -> Algorithm.HMAC_SHA256;
        };
    }

    // ---- Cavage

    private VerificationResult verifyCavage(HttpMessageView msg, VerificationPolicy policy) {
        CavageSignature.Parsed p = CavageSignature.parse(msg.headers().combined("Signature"));
        VerificationKey key = policy.keys().resolve(p.keyId())
                .orElseThrow(() -> new HttpSignatureException(Reason.UNKNOWN_KEY, "Unknown key id"));
        KeyType keyType = key.keyType();

        Algorithm alg;
        if (p.algorithm().isPresent()) {
            Algorithm declared = Algorithm.fromId(p.algorithm().get()).filter(Algorithm::isCavage).orElseThrow(
                    () -> new HttpSignatureException(Reason.UNSUPPORTED_ALGORITHM, "Unsupported algorithm " + p.algorithm().get()));
            // hs2019 takes the algorithm from the key: its pinned algorithm first, else the key type's convention
            alg = declared == Algorithm.HS2019 ? key.algorithm().orElseGet(() -> Algorithm.forHs2019(keyType)) : declared;
            if (declared != Algorithm.HS2019 && key.algorithm().isPresent() && key.algorithm().get() != alg) {
                throw new HttpSignatureException(Reason.ALGORITHM_KEY_MISMATCH, "Declared algorithm does not match the key's");
            }
        } else {
            alg = key.algorithm().orElseGet(() -> keyType == KeyType.RSA ? Algorithm.RSA_SHA256 : Algorithm.forHs2019(keyType));
        }
        if (alg.keyType() != keyType) {
            throw new HttpSignatureException(Reason.ALGORITHM_KEY_MISMATCH, "Algorithm " + alg.id() + " does not match key type " + keyType);
        }

        List<Component> covered = p.headers().stream().map(Component::of).toList();
        if (policy.strictCoverage()) {
            if (!covers(covered, "(request-target)") || !covers(covered, "host") || !covers(covered, "date")) {
                throw new HttpSignatureException(Reason.MISSING_COMPONENT, "Cavage signature must cover (request-target), host and date");
            }
            if (hasBody(msg) && !covers(covered, "digest")) {
                throw new HttpSignatureException(Reason.MISSING_COMPONENT, "Signature over a body must cover digest");
            }
        }
        requireComponents(covered, policy);
        checkDigest(msg, policy, "Digest", "Content-Digest");

        // created/expires parameters only count when they are covered by the signature; an uncovered
        // parameter is attacker-controlled and must not override the signed Date header
        Optional<Long> coveredCreated = covers(covered, "(created)") ? p.created() : Optional.empty();
        Optional<Long> coveredExpires = covers(covered, "(expires)") ? p.expires() : Optional.empty();
        Instant created = coveredCreated.map(Instant::ofEpochSecond).orElseGet(() -> dateHeader(msg));
        Optional<Instant> expires = coveredExpires.map(Instant::ofEpochSecond);
        checkTime(created, expires, policy);

        String base = SignatureBase.cavage(msg, p.headers(), coveredCreated, coveredExpires);
        if (!Jca.verify(alg, Scheme.CAVAGE, key.key(), base.getBytes(StandardCharsets.UTF_8), p.signature())) {
            throw new HttpSignatureException(Reason.INVALID_SIGNATURE, "Signature does not verify");
        }
        return new VerificationResult(Scheme.CAVAGE, p.keyId(), alg, covered, created, key);
    }

    private static Instant dateHeader(HttpMessageView msg) {
        Optional<String> date = msg.headers().first("Date");
        if (date.isEmpty()) {
            return null;
        }
        try {
            return Instant.from(DateTimeFormatter.RFC_1123_DATE_TIME.parse(date.get().strip()));
        } catch (DateTimeParseException e) {
            return null;
        }
    }

    // ---- shared checks

    private static boolean covers(List<Component> covered, String name) {
        return covered.stream().anyMatch(c -> c.name().equals(name));
    }

    private static boolean hasBody(HttpMessageView msg) {
        return msg.body().isPresent() && !msg.body().get().isEmpty();
    }

    private static void requireComponents(List<Component> covered, VerificationPolicy policy) {
        for (Component required : policy.requiredComponents()) {
            if (!covered.contains(required)) {
                throw new HttpSignatureException(Reason.MISSING_COMPONENT, "Policy requires " + required.serialized() + " to be covered");
            }
        }
    }

    private static void checkDigest(HttpMessageView msg, VerificationPolicy policy, String primary, String secondary) {
        if (!hasBody(msg)) {
            return;
        }
        byte[] body = msg.body().get().body();
        Optional<String> content = msg.headers().first("Content-Digest");
        Optional<String> legacy = msg.headers().first("Digest");
        if (content.isPresent()) {
            if (!Digests.verifyContentDigest(content.get(), body)) {
                throw new HttpSignatureException(Reason.DIGEST_MISMATCH, "Content-Digest does not match the body");
            }
            return;
        }
        if (legacy.isPresent()) {
            if (!Digests.verifyLegacyDigest(legacy.get(), body)) {
                throw new HttpSignatureException(Reason.DIGEST_MISMATCH, "Digest does not match the body");
            }
            return;
        }
        if (policy.requireDigest()) {
            throw new HttpSignatureException(Reason.MISSING_DIGEST, "Body without a " + primary + " header");
        }
    }

    private static void checkTime(Instant created, Optional<Instant> expires, VerificationPolicy policy) {
        Instant now = policy.clock().instant();
        if (created == null) {
            throw new HttpSignatureException(Reason.STALE, "Signature has no usable creation time");
        }
        if (created.isBefore(now.minus(policy.maxAge()))) {
            throw new HttpSignatureException(Reason.STALE, "Signature is older than " + policy.maxAge());
        }
        if (created.isAfter(now.plus(policy.clockSkew()))) {
            throw new HttpSignatureException(Reason.FUTURE_CREATED, "Signature was created in the future");
        }
        if (expires.isPresent() && expires.get().isBefore(now)) {
            throw new HttpSignatureException(Reason.EXPIRED, "Signature has expired");
        }
    }

    private static void checkNonce(String nonce, Optional<Instant> expires, Instant created, VerificationPolicy policy) {
        if (nonce == null || policy.nonces().isEmpty()) {
            return;
        }
        Instant until = expires.orElse(created.plus(policy.maxAge()));
        if (!policy.nonces().get().firstUse(nonce, until)) {
            throw new HttpSignatureException(Reason.REPLAY, "Nonce was already used");
        }
    }
}
