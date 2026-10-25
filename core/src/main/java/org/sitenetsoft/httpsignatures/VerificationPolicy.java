package org.sitenetsoft.httpsignatures;

import java.time.Clock;
import java.time.Duration;
import java.util.EnumSet;
import java.util.Optional;
import java.util.Set;

/**
 * Verification rules. {@link #defaults(KeyResolver)} applies the spec's security requirements: both schemes, 5 minutes
 * of clock skew, signatures at most 1 hour old, a digest required with a body, and mandatory coverage of the
 * method, target and body.
 */
public record VerificationPolicy(Set<Scheme> schemes, Duration clockSkew, Duration maxAge, boolean requireDigest,
        boolean strictCoverage, Set<Component> requiredComponents, KeyResolver keys, Optional<NonceCheck> nonces,
        Clock clock) {

    public VerificationPolicy {
        schemes = Set.copyOf(schemes);
        requiredComponents = Set.copyOf(requiredComponents);
        if (keys == null) {
            throw new IllegalArgumentException("a KeyResolver is required");
        }
        nonces = nonces == null ? Optional.empty() : nonces;
        clock = clock == null ? Clock.systemUTC() : clock;
    }

    public static VerificationPolicy defaults(KeyResolver keys) {
        return new VerificationPolicy(EnumSet.allOf(Scheme.class), Duration.ofMinutes(5), Duration.ofHours(1), true, true,
                Set.of(), keys, Optional.empty(), Clock.systemUTC());
    }

    public VerificationPolicy withSchemes(Set<Scheme> schemes) {
        return new VerificationPolicy(schemes, clockSkew, maxAge, requireDigest, strictCoverage, requiredComponents, keys, nonces, clock);
    }

    public VerificationPolicy withClockSkew(Duration clockSkew) {
        return new VerificationPolicy(schemes, clockSkew, maxAge, requireDigest, strictCoverage, requiredComponents, keys, nonces, clock);
    }

    public VerificationPolicy withMaxAge(Duration maxAge) {
        return new VerificationPolicy(schemes, clockSkew, maxAge, requireDigest, strictCoverage, requiredComponents, keys, nonces, clock);
    }

    public VerificationPolicy withRequireDigest(boolean requireDigest) {
        return new VerificationPolicy(schemes, clockSkew, maxAge, requireDigest, strictCoverage, requiredComponents, keys, nonces, clock);
    }

    /**
     * When false, the mandatory coverage rules (method, target, body) are not enforced; only
     * {@link #requiredComponents()} are. Needed to verify published test vectors; keep it on in production.
     */
    public VerificationPolicy withStrictCoverage(boolean strictCoverage) {
        return new VerificationPolicy(schemes, clockSkew, maxAge, requireDigest, strictCoverage, requiredComponents, keys, nonces, clock);
    }

    public VerificationPolicy withRequiredComponents(Set<Component> requiredComponents) {
        return new VerificationPolicy(schemes, clockSkew, maxAge, requireDigest, strictCoverage, requiredComponents, keys, nonces, clock);
    }

    public VerificationPolicy withKeys(KeyResolver keys) {
        return new VerificationPolicy(schemes, clockSkew, maxAge, requireDigest, strictCoverage, requiredComponents, keys, nonces, clock);
    }

    public VerificationPolicy withNonces(NonceCheck nonces) {
        return new VerificationPolicy(schemes, clockSkew, maxAge, requireDigest, strictCoverage, requiredComponents, keys,
                Optional.ofNullable(nonces), clock);
    }

    public VerificationPolicy withClock(Clock clock) {
        return new VerificationPolicy(schemes, clockSkew, maxAge, requireDigest, strictCoverage, requiredComponents, keys, nonces, clock);
    }
}
