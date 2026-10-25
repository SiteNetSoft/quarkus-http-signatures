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
}
