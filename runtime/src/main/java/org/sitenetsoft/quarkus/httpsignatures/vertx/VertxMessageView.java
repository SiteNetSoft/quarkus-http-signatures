package org.sitenetsoft.quarkus.httpsignatures.vertx;

import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.sitenetsoft.httpsignatures.Headers;
import org.sitenetsoft.httpsignatures.HttpMessageView;

import io.vertx.core.MultiMap;
import io.vertx.ext.web.RoutingContext;

/**
 * Adapts a Vert.x request to {@link HttpMessageView}.
 */
public final class VertxMessageView {

    private VertxMessageView() {
    }

    public static HttpMessageView of(RoutingContext ctx, byte[] body) {
        return HttpMessageView.of(ctx.request().method().name(), URI.create(ctx.request().absoluteURI()),
                headers(ctx.request().headers()), body);
    }

    public static Headers headers(MultiMap multiMap) {
        Map<String, List<String>> map = new LinkedHashMap<>();
        for (Map.Entry<String, String> e : multiMap) {
            map.computeIfAbsent(e.getKey(), k -> new ArrayList<>()).add(e.getValue());
        }
        return Headers.of(map);
    }
}
