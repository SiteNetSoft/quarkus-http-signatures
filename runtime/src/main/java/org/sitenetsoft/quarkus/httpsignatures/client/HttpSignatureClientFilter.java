package org.sitenetsoft.quarkus.httpsignatures.client;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.Method;
import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import jakarta.annotation.Priority;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.client.ClientRequestContext;
import jakarta.ws.rs.client.ClientRequestFilter;
import jakarta.ws.rs.client.ClientResponseContext;
import jakarta.ws.rs.client.ClientResponseFilter;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.ext.WriterInterceptor;
import jakarta.ws.rs.ext.WriterInterceptorContext;

import org.jboss.logging.Logger;
import org.sitenetsoft.httpsignatures.Headers;
import org.sitenetsoft.httpsignatures.Scheme;
import org.sitenetsoft.httpsignatures.SignedHeaders;

import io.quarkus.arc.Arc;

/**
 * REST Client provider that signs outbound requests. Requests without an entity are signed in the request filter;
 * requests with an entity are signed after serialization, so the digest covers the exact bytes sent. On a 401 or
 * 403 the other scheme is remembered for the host, so the next call succeeds (a filter cannot retry by itself).
 */
@Priority(Priorities.HEADER_DECORATOR)
public class HttpSignatureClientFilter implements ClientRequestFilter, WriterInterceptor, ClientResponseFilter {

    private static final Logger LOG = Logger.getLogger("org.sitenetsoft.quarkus.httpsignatures");
    static final String INVOKED_METHOD = "org.eclipse.microprofile.rest.client.invokedMethod";
    static final String PROP_URI = "org.sitenetsoft.quarkus.httpsignatures.uri";
    static final String PROP_METHOD = "org.sitenetsoft.quarkus.httpsignatures.method";
    static final String PROP_CLIENT = "org.sitenetsoft.quarkus.httpsignatures.client";
    static final String PROP_SCHEME = "org.sitenetsoft.quarkus.httpsignatures.scheme";

    private RequestSigner signer() {
        return Arc.container().instance(RequestSigner.class).get();
    }

    @Override
    public void filter(ClientRequestContext ctx) throws IOException {
        Optional<String> client = clientName(ctx);
        Scheme scheme = signer().schemeFor(ctx.getUri(), client);
        ctx.setProperty(PROP_URI, ctx.getUri());
        ctx.setProperty(PROP_METHOD, ctx.getMethod());
        ctx.setProperty(PROP_CLIENT, client.orElse(""));
        ctx.setProperty(PROP_SCHEME, scheme);
        if (!ctx.hasEntity()) {
            SignedHeaders signed = signer().sign(ctx.getMethod(), ctx.getUri(), headers(ctx.getHeaders()), null, client, scheme);
            signed.applyTo((k, v) -> ctx.getHeaders().putSingle(k, v));
        }
    }

    @Override
    public void aroundWriteTo(WriterInterceptorContext ctx) throws IOException {
        URI uri = (URI) ctx.getProperty(PROP_URI);
        if (uri == null) {
            ctx.proceed();
            return;
        }
        // tee: the framework collects its result from the original stream as soon as the writer finishes,
        // so the bytes must reach it during proceed() while we keep a copy for the digest
        OutputStream original = ctx.getOutputStream();
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        ctx.setOutputStream(new TeeOutputStream(original, buffer));
        ctx.proceed();
        byte[] body = buffer.toByteArray();
        String client = (String) ctx.getProperty(PROP_CLIENT);
        SignedHeaders signed = signer().sign((String) ctx.getProperty(PROP_METHOD), uri, headers(ctx.getHeaders()), body,
                client == null || client.isEmpty() ? Optional.empty() : Optional.of(client), (Scheme) ctx.getProperty(PROP_SCHEME));
        signed.applyTo((k, v) -> ctx.getHeaders().putSingle(k, v));
        ctx.setOutputStream(original);
    }

    private static final class TeeOutputStream extends OutputStream {
        private final OutputStream a;
        private final OutputStream b;

        TeeOutputStream(OutputStream a, OutputStream b) {
            this.a = a;
            this.b = b;
        }

        @Override
        public void write(int i) throws IOException {
            a.write(i);
            b.write(i);
        }

        @Override
        public void write(byte[] bytes, int off, int len) throws IOException {
            a.write(bytes, off, len);
            b.write(bytes, off, len);
        }

        @Override
        public void flush() throws IOException {
            a.flush();
        }

        @Override
        public void close() throws IOException {
            a.close();
        }
    }

    @Override
    public void filter(ClientRequestContext request, ClientResponseContext response) {
        int status = response.getStatus();
        Scheme used = (Scheme) request.getProperty(PROP_SCHEME);
        if (used != null && (status == 401 || status == 403) && signer().fallbackEnabled()) {
            LOG.debugf("%s rejected a %s signature (%d); next request will use %s", request.getUri().getHost(), used.id(), status, used.other().id());
            signer().memory().remember(request.getUri().getHost(), used.other());
        }
    }

    static Optional<String> clientName(ClientRequestContext ctx) {
        Object invoked = ctx.getProperty(INVOKED_METHOD);
        if (invoked instanceof Method m) {
            SignRequests ann = m.getDeclaringClass().getAnnotation(SignRequests.class);
            if (ann != null && !ann.client().isEmpty()) {
                return Optional.of(ann.client());
            }
        }
        return Optional.empty();
    }

    static Headers headers(MultivaluedMap<String, Object> headers) {
        Map<String, List<String>> map = new LinkedHashMap<>();
        headers.forEach((k, values) -> {
            List<String> list = new ArrayList<>();
            for (Object v : values) {
                if (v != null) {
                    list.add(String.valueOf(v));
                }
            }
            map.put(k, list);
        });
        return Headers.of(map);
    }
}
