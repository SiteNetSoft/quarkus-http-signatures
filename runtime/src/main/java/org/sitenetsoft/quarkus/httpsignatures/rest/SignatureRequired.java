package org.sitenetsoft.quarkus.httpsignatures.rest;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Requires a valid HTTP signature on a Quarkus REST resource method or class. Failure answers 401 with no detail.
 * {@link #components()} lists component identifiers that must be covered, for example
 * {@code {"@method", "@target-uri", "content-digest"}}.
 */
@Target({ ElementType.METHOD, ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
public @interface SignatureRequired {

    String[] components() default {};
}
