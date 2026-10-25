package org.sitenetsoft.httpsignatures;

public interface Verifier {

    /**
     * @throws HttpSignatureException when the message carries no acceptable, valid signature
     */
    VerificationResult verify(HttpMessageView msg, VerificationPolicy policy);
}
