package org.sitenetsoft.httpsignatures;

/**
 * A message body, available so the verifier can check digests against the actual bytes.
 */
public record BodyDigest(byte[] body) {

    public BodyDigest {
        body = body == null ? new byte[0] : body.clone();
    }

    public static BodyDigest of(byte[] body) {
        return new BodyDigest(body);
    }

    public boolean isEmpty() {
        return body.length == 0;
    }

    public String contentDigest(DigestAlgorithm alg) {
        return Digests.contentDigest(body, alg);
    }

    public String legacyDigest() {
        return Digests.legacyDigest(body);
    }
}
