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
