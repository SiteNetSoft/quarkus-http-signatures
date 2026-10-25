package org.sitenetsoft.httpsignatures;

import java.net.URI;
import java.util.Optional;
import java.util.OptionalInt;

record SimpleHttpMessage(String method, URI targetUri, Headers headers, Optional<BodyDigest> body, OptionalInt status)
        implements HttpMessageView {

    SimpleHttpMessage {
        method = method == null ? "" : method;
        headers = headers == null ? Headers.empty() : headers;
        body = body == null ? Optional.empty() : body;
    }
}
