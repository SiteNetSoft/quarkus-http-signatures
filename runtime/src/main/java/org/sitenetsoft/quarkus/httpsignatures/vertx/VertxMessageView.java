package org.sitenetsoft.quarkus.httpsignatures.vertx;

import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.sitenetsoft.httpsignatures.Headers;
import org.sitenetsoft.httpsignatures.HttpMessageView;

import io.vertx.core.MultiMap;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.ext.web.RoutingContext;

/**
 * Adapts a Vert.x request to {@link HttpMessageView}.
 */
public final class VertxMessageView {

    private VertxMessageView() {
    }

    public static HttpMessageView of(RoutingContext ctx, byte[] body) {
        return of(ctx.request(), body);
    }

    public static HttpMessageView of(HttpServerRequest request, byte[] body) {
        return HttpMessageView.of(request.method().name(), URI.create(request.absoluteURI()), headers(request), body);
    }

    /**
     * The request headers; over HTTP/2 the {@code :authority} pseudo-header stands in for a missing {@code Host}, so
     * Cavage signatures covering {@code host} still verify.
     */
    public static Headers headers(HttpServerRequest request) {
        Map<String, List<String>> map = toMap(request.headers());
        if (!map.keySet().stream().anyMatch(k -> k.equalsIgnoreCase("Host")) && request.authority() != null) {
            map.put("Host", List.of(request.authority().toString()));
        }
        return Headers.of(map);
    }

    public static Headers headers(MultiMap multiMap) {
        return Headers.of(toMap(multiMap));
    }

    private static Map<String, List<String>> toMap(MultiMap multiMap) {
        Map<String, List<String>> map = new LinkedHashMap<>();
        for (Map.Entry<String, String> e : multiMap) {
            map.computeIfAbsent(e.getKey(), k -> new ArrayList<>()).add(e.getValue());
        }
        return map;
    }
}
