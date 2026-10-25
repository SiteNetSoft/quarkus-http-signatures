package org.sitenetsoft.quarkus.httpsignatures.vertx;

import io.quarkus.arc.Arc;
import io.quarkus.runtime.annotations.RecordableConstructor;
import io.vertx.core.Handler;
import io.vertx.ext.web.RoutingContext;

/**
 * Resolves a {@code Handler<RoutingContext>} bean on first use, so recorders never touch the container at static
 * init.
 */
public final class LazyBeanHandler implements Handler<RoutingContext> {

    private final String beanClassName;
    private volatile Handler<RoutingContext> delegate;

    @RecordableConstructor
    public LazyBeanHandler(String beanClassName) {
        this.beanClassName = beanClassName;
    }

    public String getBeanClassName() {
        return beanClassName;
    }

    @Override
    @SuppressWarnings("unchecked")
    public void handle(RoutingContext ctx) {
        Handler<RoutingContext> h = delegate;
        if (h == null) {
            try {
                Class<?> type = Thread.currentThread().getContextClassLoader().loadClass(beanClassName);
                h = (Handler<RoutingContext>) Arc.container().instance(type).get();
            } catch (ClassNotFoundException e) {
                throw new IllegalStateException(e);
            }
            delegate = h;
        }
        h.handle(ctx);
    }
}
