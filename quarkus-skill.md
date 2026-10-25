# quarkus-http-signatures — skill notes for coding agents

- Static keys: `quarkus.http-signatures.keys."<id>".location=<pem or jwk file>`; the key id is the map key.
- Verify incoming requests: annotate a Quarkus REST method with `@SignatureRequired`, list path patterns in
  `quarkus.http-signatures.verify.paths`, or rely on Quarkus Security (`@Authenticated`, HTTP policies): a verified
  signature becomes a `SecurityIdentity` whose principal is the key id.
- Sign outgoing requests: `@RegisterProvider(HttpSignatureClientFilter.class)` plus `@SignRequests(client="name")` on a REST Client interface, or `SigningHttpClient` for `java.net.http` (does the double knock).
- Replace `KeyResolver` to fetch remote keys (e.g. ActivityPub actors). Results are cached; a verification failure
  refetches once.
- Scheme is detected automatically: `Signature-Input` means RFC 9421, a lone `Signature` means Cavage.
- Never log signature values or keys. In dev/test the signature base is logged at DEBUG on failures.
- Behind a reverse proxy or TLS termination set `quarkus.http.proxy.proxy-address-forwarding=true` (plus forwarded host/prefix) or RFC 9421 `@target-uri` checks fail.
- Signed request bodies are buffered up to `quarkus.http-signatures.verify.max-body-size` (10M); larger bodies get 413.
