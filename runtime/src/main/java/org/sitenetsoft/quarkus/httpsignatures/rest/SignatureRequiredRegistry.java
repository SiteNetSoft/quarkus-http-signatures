package org.sitenetsoft.quarkus.httpsignatures.rest;

import java.util.Set;

/**
 * The resource classes that carry {@link SignatureRequired} on the class or on one of their methods, collected from the
 * Jandex index at build time. The REST filter consults this set before touching reflection, so resources without the
 * annotation cost nothing per request and need no reflection metadata in a native image.
 */
public final class SignatureRequiredRegistry {

    private final Set<String> classNames;

    public SignatureRequiredRegistry(Set<String> classNames) {
        this.classNames = Set.copyOf(classNames);
    }

    /** Whether {@code resourceClass} (or a superclass of it) was annotated at build time. */
    public boolean applies(Class<?> resourceClass) {
        for (Class<?> c = resourceClass; c != null && c != Object.class; c = c.getSuperclass()) {
            if (classNames.contains(c.getName())) {
                return true;
            }
        }
        return false;
    }

    public Set<String> classNames() {
        return classNames;
    }
}
