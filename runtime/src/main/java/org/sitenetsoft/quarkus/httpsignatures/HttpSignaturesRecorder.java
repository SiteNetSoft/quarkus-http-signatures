package org.sitenetsoft.quarkus.httpsignatures;

import org.sitenetsoft.quarkus.httpsignatures.vertx.LazyBeanHandler;
import org.sitenetsoft.quarkus.httpsignatures.vertx.VertxSignatureHandler;

import io.quarkus.runtime.annotations.Recorder;
import io.vertx.core.Handler;
import io.vertx.ext.web.RoutingContext;

@Recorder
public class HttpSignaturesRecorder {

    public Handler<RoutingContext> pathHandler() {
        return new LazyBeanHandler(VertxSignatureHandler.class.getName());
    }

    /** The classes found annotated with {@code @SignatureRequired} at build time, as a singleton bean supplier. */
    public java.util.function.Supplier<org.sitenetsoft.quarkus.httpsignatures.rest.SignatureRequiredRegistry> signatureRequiredRegistry(
            java.util.Set<String> classNames) {
        java.util.Set<String> names = java.util.Set.copyOf(classNames);
        return () -> new org.sitenetsoft.quarkus.httpsignatures.rest.SignatureRequiredRegistry(names);
    }
}
