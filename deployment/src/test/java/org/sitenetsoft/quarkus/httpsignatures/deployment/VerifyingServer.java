package org.sitenetsoft.quarkus.httpsignatures.deployment;

import java.net.URI;
import java.security.Key;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import org.sitenetsoft.httpsignatures.Headers;
import org.sitenetsoft.httpsignatures.HttpMessageView;
import org.sitenetsoft.httpsignatures.HttpSignatureException;
import org.sitenetsoft.httpsignatures.HttpVerifier;
import org.sitenetsoft.httpsignatures.Keys;
import org.sitenetsoft.httpsignatures.Scheme;
import org.sitenetsoft.httpsignatures.VerificationKey;
import org.sitenetsoft.httpsignatures.VerificationPolicy;
import org.sitenetsoft.httpsignatures.VerificationResult;
import org.sitenetsoft.quarkus.httpsignatures.vertx.VertxMessageView;

import io.vertx.core.Vertx;
import io.vertx.core.http.HttpServer;
import io.vertx.core.http.HttpServerRequest;

/**
 * A plain Vert.x server that verifies every request with the core verifier against key {@code k1}. In
 * {@code cavageOnly} mode RFC 9421 signatures are answered with 401, like a Fediverse server that predates RFC 9421.
 */
public final class VerifyingServer {

    private final Vertx vertx = Vertx.vertx();
    private final HttpServer server;
    private final AtomicInteger requests = new AtomicInteger();
    private volatile boolean cavageOnly;
    private final VerificationPolicy policy;

    public VerifyingServer() {
        List<Key> keys = Keys.parsePemAll(TestSigning.resource("keys/ed25519.pem"));
        PublicKey pub = keys.stream().filter(PublicKey.class::isInstance).map(PublicKey.class::cast).findFirst().orElseThrow();
        VerificationKey vk = new VerificationKey("k1", Optional.empty(), pub);
        policy = VerificationPolicy.defaults(id -> "k1".equals(id) ? Optional.of(vk) : Optional.empty());
        server = vertx.createHttpServer().requestHandler(this::handle);
        server.listen(0, "127.0.0.1").toCompletionStage().toCompletableFuture().join();
    }

    public int port() {
        return server.actualPort();
    }

    public int requests() {
        return requests.get();
    }

    public void cavageOnly(boolean value) {
        cavageOnly = value;
    }

    public void stop() {
        vertx.close().toCompletionStage().toCompletableFuture().join();
    }

    private void handle(HttpServerRequest req) {
        requests.incrementAndGet();
        req.body().onSuccess(buf -> {
            HttpMessageView msg = VertxMessageView.of(req, buf == null ? null : buf.getBytes());
            try {
                if (cavageOnly && HttpVerifier.detect(msg) == Scheme.RFC9421) {
                    req.response().setStatusCode(401).end("rfc9421 not understood");
                    return;
                }
                VerificationResult r = new HttpVerifier().verify(msg, policy);
                req.response().end("scheme=" + r.scheme().id() + " key=" + r.keyId() + " body=" + (buf == null ? 0 : buf.length()));
            } catch (HttpSignatureException e) {
                req.response().setStatusCode(401).end(e.reason().name() + ": " + e.getMessage() + " headers=" + req.headers().names());
            }
        });
    }
}
