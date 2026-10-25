package org.sitenetsoft.quarkus.httpsignatures.client;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a REST Client interface whose requests are signed by {@link HttpSignatureClientFilter}. Register the filter
 * with {@code @RegisterProvider(HttpSignatureClientFilter.class)}; {@link #client()} names the
 * {@code quarkus.http-signatures.clients."<name>"} settings to use.
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
public @interface SignRequests {

    String client() default "";
}
