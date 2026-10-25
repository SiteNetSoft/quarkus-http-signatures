package org.sitenetsoft.httpsignatures;

public interface Signer {

    SignedHeaders sign(HttpMessageView msg, SignatureSpec spec, SigningKey key);
}
