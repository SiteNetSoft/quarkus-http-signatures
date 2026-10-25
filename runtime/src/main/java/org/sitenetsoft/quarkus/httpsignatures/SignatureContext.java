package org.sitenetsoft.quarkus.httpsignatures;

import java.util.Optional;

import jakarta.enterprise.context.RequestScoped;

import org.sitenetsoft.httpsignatures.VerificationResult;

/**
 * The verified signature of the current request, when there is one.
 */
@RequestScoped
public class SignatureContext {

    private VerificationResult result;

    public boolean isVerified() {
        return result != null;
    }

    public Optional<VerificationResult> result() {
        return Optional.ofNullable(result);
    }

    public void set(VerificationResult result) {
        this.result = result;
    }
}
