# Webhook example

A Quarkus app that accepts webhook deliveries only when they carry a valid HMAC-SHA256 signature (RFC 9421 or
Cavage) over the method, target URI and body. No ActivityPub involved.

- `WebhookResource`: `@SignatureRequired(components = {"@method", "@target-uri", "content-digest"})`.
- `application.properties`: the shared secret as a JWK (`kty: oct`).
- `WebhookResourceTest`: signs a delivery with `SigningHttpClient` and checks that unsigned and tampered deliveries
  get `401`.

Run `mvn test` after installing `quarkus-http-signatures` from the repository root.
