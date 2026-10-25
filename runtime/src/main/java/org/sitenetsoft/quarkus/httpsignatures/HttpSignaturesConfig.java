package org.sitenetsoft.quarkus.httpsignatures;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.sitenetsoft.httpsignatures.Algorithm;
import org.sitenetsoft.httpsignatures.Scheme;

import io.quarkus.runtime.annotations.ConfigDocMapKey;
import io.quarkus.runtime.annotations.ConfigPhase;
import io.quarkus.runtime.annotations.ConfigRoot;
import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithConverter;
import io.smallrye.config.WithDefault;

@ConfigMapping(prefix = "quarkus.http-signatures")
@ConfigRoot(phase = ConfigPhase.RUN_TIME)
public interface HttpSignaturesConfig {

    /**
     * Verification settings.
     */
    Verify verify();

    /**
     * Outbound signing settings.
     */
    Sign sign();

    /**
     * Static keys, by key id.
     */
    @ConfigDocMapKey("key-id")
    Map<String, KeyConfig> keys();

    /**
     * Cache for resolved verification keys.
     */
    KeyCache keyCache();

    /**
     * Replay protection.
     */
    Nonce nonce();

    /**
     * Named outbound clients.
     */
    @ConfigDocMapKey("client-name")
    Map<String, ClientConfig> clients();

    interface Verify {
        /**
         * Allowed drift of {@code created} (or {@code Date}) into the future.
         */
        @WithDefault("5m")
        Duration clockSkew();

        /**
         * Oldest signature accepted.
         */
        @WithDefault("1h")
        Duration maxAge();

        /**
         * Reject bodies without a {@code Content-Digest} or {@code Digest} header.
         */
        @WithDefault("true")
        boolean requireDigest();

        /**
         * Schemes accepted: {@code rfc9421}, {@code cavage}.
         */
        @WithDefault("rfc9421,cavage")
        List<@WithConverter(SchemeConverter.class) Scheme> schemes();

        /**
         * Vert.x path patterns (for example {@code /inbox/*}) that require a valid signature.
         */
        Optional<List<String>> paths();
    }

    interface Sign {
        /**
         * Scheme tried first for outbound requests.
         */
        @WithDefault("rfc9421")
        @WithConverter(SchemeConverter.class)
        Scheme preferredScheme();

        /**
         * Retry once with the other scheme on 401/403 and remember the answer per host.
         */
        @WithDefault("true")
        boolean fallback();
    }

    interface KeyConfig {
        /**
         * PEM or JWK file: a classpath resource, a plain path or a {@code file:} URL.
         */
        String location();

        /**
         * Algorithm to sign with; defaults from the key type.
         */
        Optional<@WithConverter(AlgorithmConverter.class) Algorithm> algorithm();
    }

    interface KeyCache {
        /**
         * How long resolved verification keys are cached.
         */
        @WithDefault("1h")
        Duration ttl();
    }

    interface Nonce {
        /**
         * Enable nonce-based replay protection.
         */
        @WithDefault("false")
        boolean enabled();
    }

    interface ClientConfig {
        /**
         * Static key id this client signs with.
         */
        Optional<String> keyId();

        /**
         * Scheme for this client, overriding {@code quarkus.http-signatures.sign.preferred-scheme}.
         */
        Optional<@WithConverter(SchemeConverter.class) Scheme> scheme();

        /**
         * Covered components, overriding the scheme's defaults.
         */
        Optional<List<String>> components();
    }
}
