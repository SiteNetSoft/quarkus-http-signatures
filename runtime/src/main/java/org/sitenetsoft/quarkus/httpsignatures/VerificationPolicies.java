package org.sitenetsoft.quarkus.httpsignatures;

import java.util.EnumSet;
import java.util.Set;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;

import org.sitenetsoft.httpsignatures.Component;
import org.sitenetsoft.httpsignatures.Scheme;
import org.sitenetsoft.httpsignatures.VerificationPolicy;

/**
 * Builds the {@link VerificationPolicy} from config, the caching resolver and the nonce store.
 */
@ApplicationScoped
public class VerificationPolicies {

    private final HttpSignaturesConfig config;
    private final CachingKeyResolver keys;
    private final Instance<NonceStore> nonces;

    @Inject
    public VerificationPolicies(HttpSignaturesConfig config, CachingKeyResolver keys, Instance<NonceStore> nonces) {
        this.config = config;
        this.keys = keys;
        this.nonces = nonces;
    }

    public VerificationPolicy current() {
        Set<Scheme> schemes = config.verify().schemes().isEmpty() ? EnumSet.allOf(Scheme.class) : EnumSet.copyOf(config.verify().schemes());
        VerificationPolicy p = VerificationPolicy.defaults(keys.asResolver())
                .withSchemes(schemes)
                .withClockSkew(config.verify().clockSkew())
                .withMaxAge(config.verify().maxAge())
                .withRequireDigest(config.verify().requireDigest());
        if (config.nonce().enabled() && nonces.isResolvable()) {
            p = p.withNonces(nonces.get());
        }
        return p;
    }

    public VerificationPolicy requiring(String... components) {
        Set<Component> required = new java.util.HashSet<>();
        for (String c : components) {
            required.add(Component.of(c));
        }
        return current().withRequiredComponents(required);
    }
}
