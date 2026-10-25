package org.sitenetsoft.quarkus.httpsignatures;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import javax.crypto.SecretKey;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.jboss.logging.Logger;
import org.sitenetsoft.httpsignatures.Algorithm;
import org.sitenetsoft.httpsignatures.KeyType;
import org.sitenetsoft.httpsignatures.Keys;
import org.sitenetsoft.httpsignatures.SigningKey;
import org.sitenetsoft.httpsignatures.VerificationKey;

/**
 * Keys declared under {@code quarkus.http-signatures.keys."<id>"}, loaded on first use.
 */
@ApplicationScoped
public class StaticKeys {

    private static final Logger LOG = Logger.getLogger("org.sitenetsoft.quarkus.httpsignatures");

    record Loaded(Optional<SigningKey> signing, Optional<VerificationKey> verification) {
    }

    private final HttpSignaturesConfig config;
    private final Map<String, Loaded> loaded = new ConcurrentHashMap<>();

    @Inject
    public StaticKeys(HttpSignaturesConfig config) {
        this.config = config;
    }

    public java.util.Set<String> ids() {
        return config.keys().keySet();
    }

    public Optional<SigningKey> signing(String id) {
        return load(id).flatMap(Loaded::signing);
    }

    public Optional<VerificationKey> verification(String id) {
        return load(id).flatMap(Loaded::verification);
    }

    private Optional<Loaded> load(String id) {
        HttpSignaturesConfig.KeyConfig kc = config.keys().get(id);
        if (kc == null) {
            return Optional.empty();
        }
        return Optional.of(loaded.computeIfAbsent(id, k -> read(id, kc)));
    }

    private Loaded read(String id, HttpSignaturesConfig.KeyConfig kc) {
        String content = readLocation(kc.location());
        List<Key> keys = kc.location().endsWith(".jwk") || kc.location().endsWith(".json") || content.strip().startsWith("{")
                ? List.of(Keys.parseJwk(content))
                : Keys.parsePemAll(content);
        if (keys.isEmpty()) {
            throw new IllegalStateException("No key found in " + kc.location() + " for quarkus.http-signatures.keys." + id);
        }
        PrivateKey priv = keys.stream().filter(PrivateKey.class::isInstance).map(PrivateKey.class::cast).findFirst().orElse(null);
        PublicKey pub = keys.stream().filter(PublicKey.class::isInstance).map(PublicKey.class::cast).findFirst().orElse(null);
        SecretKey secret = keys.stream().filter(SecretKey.class::isInstance).map(SecretKey.class::cast).findFirst().orElse(null);
        if (pub == null && priv instanceof RSAPrivateCrtKey crt) {
            try {
                pub = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(crt.getModulus(), crt.getPublicExponent()));
            } catch (java.security.GeneralSecurityException e) {
                LOG.debugf("Could not derive public key for %s", id);
            }
        }
        Key anyKey = secret != null ? secret : priv != null ? priv : pub;
        Algorithm algorithm = kc.algorithm().orElseGet(() -> defaultAlgorithm(KeyType.of(anyKey)));
        Optional<SigningKey> signing = Optional.empty();
        Optional<VerificationKey> verification = Optional.empty();
        if (secret != null) {
            signing = Optional.of(new SigningKey(id, algorithm, secret));
            verification = Optional.of(new VerificationKey(id, Optional.of(algorithm), secret));
        } else {
            if (priv != null) {
                signing = Optional.of(new SigningKey(id, algorithm, priv));
            }
            if (pub != null) {
                verification = Optional.of(new VerificationKey(id, kc.algorithm(), pub));
            }
        }
        LOG.debugf("Loaded static key '%s' (%s)", id, KeyType.of(anyKey));
        return new Loaded(signing, verification);
    }

    /**
     * The algorithm used for a key when none is configured.
     */
    public static Algorithm defaultAlgorithm(KeyType type) {
        return switch (type) {
            case RSA -> Algorithm.RSA_V1_5_SHA256;
            case EC_P256 -> Algorithm.ECDSA_P256_SHA256;
            case EC_P384 -> Algorithm.ECDSA_P384_SHA384;
            case ED25519 -> Algorithm.ED25519;
            case HMAC -> Algorithm.HMAC_SHA256;
        };
    }

    static String readLocation(String location) {
        try {
            if (location.startsWith("file:")) {
                return Files.readString(Path.of(URI.create(location)));
            }
            Path path = Path.of(location);
            if (Files.isRegularFile(path)) {
                return Files.readString(path);
            }
            ClassLoader cl = Thread.currentThread().getContextClassLoader();
            String resource = location.startsWith("/") ? location.substring(1) : location;
            try (InputStream in = cl.getResourceAsStream(resource)) {
                if (in == null) {
                    throw new IllegalStateException("Key file not found: " + location);
                }
                return new String(in.readAllBytes(), StandardCharsets.UTF_8);
            }
        } catch (IOException e) {
            throw new IllegalStateException("Cannot read key file " + location, e);
        }
    }
}
