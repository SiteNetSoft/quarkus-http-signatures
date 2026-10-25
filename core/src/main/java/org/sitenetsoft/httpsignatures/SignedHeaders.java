package org.sitenetsoft.httpsignatures;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.BiConsumer;

/**
 * Headers to add to a message after signing: the signature headers plus any {@code Content-Digest}, {@code Digest}
 * or {@code Date} the signer had to add.
 */
public record SignedHeaders(Map<String, String> headers) {

    public SignedHeaders {
        headers = Collections.unmodifiableMap(new LinkedHashMap<>(headers));
    }

    public void applyTo(BiConsumer<String, String> setter) {
        headers.forEach(setter);
    }

    @Override
    public String toString() {
        return "SignedHeaders" + headers.keySet();
    }
}
