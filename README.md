# quarkus-http-signatures

Sign and verify HTTP messages under [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421) and the older
[Cavage draft 12](https://datatracker.ietf.org/doc/html/draft-cavage-http-signatures-12), with body digests
(RFC 9530 `Content-Digest` and legacy `Digest`). Both schemes matter because the Fediverse still runs mostly on
Cavage while newer servers accept both. The same module serves webhooks and API-to-API authentication with no
ActivityPub involved.

| Artifact | Purpose |
| --- | --- |
| `http-signatures-core` | Plain library: signature base, signing, verification, structured fields, digests, key parsing. No HTTP framework. |
| `quarkus-http-signatures` | Extension: Vert.x, Quarkus REST, REST Client and Quarkus Security integration, config keys, Dev UI. |

Minimum supported Quarkus: **3.40 (LTS)**. Status: experimental, version 0.1.

## Quick start

```properties
quarkus.http-signatures.keys.hook.location=keys/hook.jwk
quarkus.http-signatures.keys.hook.algorithm=hmac-sha256
```

```java
@POST @Path("/webhook")
@SignatureRequired(components = {"@method", "@target-uri", "content-digest"})
public void receive(String body) { ... }
```

Outbound: `@RegisterProvider(HttpSignatureClientFilter.class) @SignRequests` on a REST Client interface, or
`SigningHttpClient.send(...)` for `java.net.http` (with double knocking: RFC 9421 first, Cavage on 401/403,
remembered per host).

## Configuration

| Property | Default | Purpose |
| --- | --- | --- |
| `quarkus.http-signatures.verify.clock-skew` | `5m` | Allowed drift on `created` or `Date` |
| `quarkus.http-signatures.verify.max-age` | `1h` | Oldest signature accepted |
| `quarkus.http-signatures.verify.require-digest` | `true` | Reject bodies without a digest |
| `quarkus.http-signatures.verify.schemes` | `rfc9421,cavage` | Schemes accepted |
| `quarkus.http-signatures.verify.paths` | none | Path patterns for the Vert.x handler |
| `quarkus.http-signatures.sign.preferred-scheme` | `rfc9421` | First scheme tried outbound |
| `quarkus.http-signatures.sign.fallback` | `true` | Retry with the other scheme on 401/403 |
| `quarkus.http-signatures.keys."<id>".location` | none | PEM or JWK file for a static key |
| `quarkus.http-signatures.key-cache.ttl` | `1h` | Resolved-key cache lifetime |
| `quarkus.http-signatures.nonce.enabled` | `false` | Enable replay protection |

See `docs/` for the full guide and `examples/webhook` for an HMAC webhook receiver with no ActivityPub dependency.

## Building

`JAVA_HOME=/path/to/jdk21 mvn -T 8 install`, then `cd examples/webhook && mvn test`.
