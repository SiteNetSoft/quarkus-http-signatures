package org.sitenetsoft.httpsignatures;

import java.time.Instant;
import java.util.List;

public record VerificationResult(Scheme scheme, String keyId, Algorithm alg, List<Component> covered, Instant created,
        VerificationKey key) {

    public VerificationResult {
        covered = List.copyOf(covered);
    }

    public boolean covers(String componentName) {
        return covered.stream().anyMatch(c -> c.name().equals(componentName));
    }
}
