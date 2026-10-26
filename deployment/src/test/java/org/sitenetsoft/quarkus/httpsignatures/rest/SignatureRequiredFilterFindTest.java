package org.sitenetsoft.quarkus.httpsignatures.rest;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.lang.reflect.Method;
import java.util.Set;

import jakarta.ws.rs.container.ResourceInfo;

import org.junit.jupiter.api.Test;

/**
 * The filter must not touch reflection for resources the build-time registry does not list (native images carry no
 * method metadata for them), and must fall back to the class-level annotation when the method lookup fails.
 */
class SignatureRequiredFilterFindTest {

    static class Plain {
        public String get() {
            return "";
        }
    }

    @SignatureRequired(components = { "@method" })
    static class Annotated {
        public String get() {
            return "";
        }
    }

    /** A {@link ResourceInfo} whose method lookup fails the way it does in a native image without reflection metadata. */
    static ResourceInfo info(Class<?> resource, boolean methodLookupThrows) {
        return new ResourceInfo() {
            @Override
            public Method getResourceMethod() {
                if (methodLookupThrows) {
                    throw new RuntimeException(new NoSuchMethodException(resource.getName() + ".get()"));
                }
                throw new AssertionError("reflective method lookup must not happen for " + resource.getName());
            }

            @Override
            public Class<?> getResourceClass() {
                return resource;
            }
        };
    }

    @Test
    void unregisteredResourceIsSkippedWithoutReflection() {
        SignatureRequiredRegistry registry = new SignatureRequiredRegistry(Set.of(Annotated.class.getName()));
        assertNull(SignatureRequiredFilter.find(registry, info(Plain.class, false)));
    }

    @Test
    void registeredResourceFallsBackToClassAnnotationWhenMethodLookupFails() {
        SignatureRequiredRegistry registry = new SignatureRequiredRegistry(Set.of(Annotated.class.getName()));
        SignatureRequired required = SignatureRequiredFilter.find(registry, info(Annotated.class, true));
        assertNotNull(required);
        assertArrayEquals(new String[] { "@method" }, required.components());
    }

    @Test
    void nullResourceClassIsSkipped() {
        SignatureRequiredRegistry registry = new SignatureRequiredRegistry(Set.of());
        assertNull(SignatureRequiredFilter.find(registry, new ResourceInfo() {
            @Override
            public Method getResourceMethod() {
                throw new AssertionError("must not be called");
            }

            @Override
            public Class<?> getResourceClass() {
                return null;
            }
        }));
    }
}
