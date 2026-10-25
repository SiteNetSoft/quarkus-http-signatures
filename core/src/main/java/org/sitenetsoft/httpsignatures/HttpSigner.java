package org.sitenetsoft.httpsignatures;

import java.nio.charset.StandardCharsets;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.sitenetsoft.httpsignatures.StructuredFields.InnerList;
import org.sitenetsoft.httpsignatures.StructuredFields.Item;

/**
 * Signs messages under either scheme. Adds {@code Content-Digest} (RFC 9421) or {@code Digest} and {@code Date}
 * (Cavage) when the message lacks them and the spec covers them.
 */
public final class HttpSigner implements Signer {

    public static final String DEFAULT_LABEL = "sig1";

    @Override
    public SignedHeaders sign(HttpMessageView msg, SignatureSpec spec, SigningKey key) {
        return sign(msg, spec, key, DEFAULT_LABEL);
    }

    public SignedHeaders sign(HttpMessageView msg, SignatureSpec spec, SigningKey key, String label) {
        if (!spec.keyId().equals(key.keyId())) {
            throw new IllegalArgumentException("spec key id " + spec.keyId() + " differs from signing key id " + key.keyId());
        }
        return spec.scheme() == Scheme.RFC9421 ? rfc9421(msg, spec, key, label) : cavage(msg, spec, key);
    }

    private SignedHeaders rfc9421(HttpMessageView msg, SignatureSpec spec, SigningKey key, String label) {
        Map<String, String> added = new LinkedHashMap<>();
        if (spec.covers("content-digest") && msg.body().isPresent() && !msg.headers().contains("Content-Digest")) {
            added.put("Content-Digest", msg.body().get().contentDigest(DigestAlgorithm.SHA_256));
        }
        HttpMessageView view = withHeaders(msg, added);

        Map<String, Object> params = new LinkedHashMap<>();
        params.put("created", spec.created().getEpochSecond());
        spec.expires().ifPresent(e -> params.put("expires", e.getEpochSecond()));
        params.put("keyid", spec.keyId());
        spec.nonce().ifPresent(n -> params.put("nonce", n));
        spec.tag().ifPresent(t -> params.put("tag", t));
        List<Item> items = new ArrayList<>();
        for (Component c : spec.covered()) {
            Map<String, Object> p = new LinkedHashMap<>();
            c.params().forEach(p::put);
            items.add(new Item(c.name(), p));
        }
        InnerList inner = new InnerList(items, params);
        String serializedParams = StructuredFields.serializeInnerList(inner);
        String base = SignatureBase.rfc9421(view, spec.covered(), serializedParams);
        byte[] sig = Jca.sign(spec.alg(), Scheme.RFC9421, key.key(), base.getBytes(StandardCharsets.UTF_8));

        added.put("Signature-Input", label + "=" + serializedParams);
        added.put("Signature", label + "=" + StructuredFields.serializeItem(new Item(sig, Map.of())));
        return new SignedHeaders(added);
    }

    private SignedHeaders cavage(HttpMessageView msg, SignatureSpec spec, SigningKey key) {
        Map<String, String> added = new LinkedHashMap<>();
        if (spec.covers("date") && !msg.headers().contains("Date")) {
            added.put("Date", DateTimeFormatter.RFC_1123_DATE_TIME.format(spec.created().atOffset(ZoneOffset.UTC)));
        }
        if (spec.covers("digest") && msg.body().isPresent() && !msg.headers().contains("Digest")) {
            added.put("Digest", msg.body().get().legacyDigest());
        }
        HttpMessageView view = withHeaders(msg, added);
        List<String> headerNames = spec.covered().stream().map(Component::name).toList();
        Optional<Long> created = spec.covers("(created)") ? Optional.of(spec.created().getEpochSecond()) : Optional.empty();
        Optional<Long> expires = spec.covers("(expires)") ? spec.expires().map(e -> e.getEpochSecond()) : Optional.empty();
        String base = SignatureBase.cavage(view, headerNames, created, expires);
        Algorithm concrete = spec.alg() == Algorithm.HS2019 ? Algorithm.forHs2019(key.keyType()) : spec.alg();
        byte[] sig = Jca.sign(concrete, Scheme.CAVAGE, key.key(), base.getBytes(StandardCharsets.UTF_8));
        added.put("Signature", CavageSignature.serialize(spec.keyId(), spec.alg().id(), headerNames, sig, created, expires));
        return new SignedHeaders(added);
    }

    static HttpMessageView withHeaders(HttpMessageView msg, Map<String, String> added) {
        if (added.isEmpty()) {
            return msg;
        }
        Map<String, List<String>> all = new LinkedHashMap<>();
        for (String n : msg.headers().names()) {
            all.put(n, msg.headers().values(n));
        }
        added.forEach((k, v) -> all.put(k, List.of(v)));
        Headers headers = Headers.of(all);
        return new SimpleHttpMessage(msg.method(), msg.targetUri(), headers, msg.body(), msg.status());
    }
}
