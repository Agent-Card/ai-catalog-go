<!--
Copyright AI-Catalog Contributors (https://github.com/Agent-Card)
SPDX-License-Identifier: Apache-2.0
-->

# AI Catalog Go SDK

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/Agent-Card/ai-catalog-go/badge)](https://securityscorecards.dev/viewer/?uri=github.com/Agent-Card/ai-catalog-go)

A Go toolkit for consuming and validating [AI Catalog](https://ai-catalog.io/) documents, the JSON format for making AI artifacts (MCP servers, A2A agents, datasets, model cards, nested catalogs, …) discoverable.

It implements the [AI Catalog specification](https://ai-catalog.io/spec/).

## Scope

The repository follows the spec's split between normative and non-normative content:

- **Normative**: the stable, supported API. Document types, parsing and querying (`catalog`), conformance validation (`validate`), digest verification and canonicalization (`trust`), and finding a site's catalog (`discovery`). `catalog` also has lookups the spec does not define, such as `GetByTag`, `GetByPublisher` and `SearchByRegex`.
- **Non-normative**:
  - `provider` and the `catalog.Source` interface load a catalog from a local file or an HTTP endpoint.
  - [`examples/`](./examples) holds reference code, such as packaging a catalog as an OCI artifact. It is not part of the supported API.

## Installation

```bash
go get github.com/Agent-Card/ai-catalog-go
```

The minimum Go version is declared in [`go.mod`](./go.mod).

## Usage

### Load a catalog

The `provider` package returns a `catalog.Source`. Nested catalog entries are not resolved; follow them yourself.

```go
import (
	"context"

	"github.com/Agent-Card/ai-catalog-go/catalog"
	"github.com/Agent-Card/ai-catalog-go/provider"
)

ctx := context.Background()

// From a local file:
src, err := provider.JSON("ai-catalog.json")

// From an explicit URL:
src, err = provider.Web(ctx, "https://acme-corp.com/catalogs/finance.json")

// From a domain's well-known URI (RFC 8615):
src, err = provider.Web(ctx, "https://acme-corp.com"+catalog.WellKnownPath)
```

`Web` fetches over HTTP. Use `provider.WithHTTPClient(myClient)` for a custom client or `provider.WithFetcher(...)` for a custom transport.

A parsed `*catalog.AICatalog` needs no `Source`; call its methods directly.

### Discover a catalog from a domain

`discovery.Discover` takes a URL or a bare domain and follows the spec's [discovery procedure](https://ai-catalog.io/spec/#discovery): a catalog at the URL itself, then a `Link` header with `rel="ai-catalog"`, then an HTML `<link rel="ai-catalog">`, then `/.well-known/ai-catalog.json`.

```go
import "github.com/Agent-Card/ai-catalog-go/discovery"

result, err := discovery.Discover(ctx, "example.com")
if err != nil {
	// errors.Is(err, discovery.ErrNotFound) when nothing was found; a
	// *discovery.NotFoundError lists every URL that was tried and why it failed.
}

result.URL     // where the catalog was served from, after redirects
result.Method  // discovery.MethodLinkHeader, MethodHTMLLink, MethodWellKnown or MethodDirect
result.Catalog // the parsed *catalog.AICatalog
result.Raw     // the bytes as served, for signature verification
```

Only `https` is requested, redirects to `http` are refused, and responses are capped at 10 MiB. Discovery does not guard against requests to private addresses; a service that runs it for callers it does not trust should pass `discovery.WithFetcher(...)` (or `WithHTTPClient` with a restricting dialer). Nested catalogs are not followed.

### Query entries

`Source.Load` returns the whole catalog as a `*catalog.AICatalog`. Its query methods cover that document's entries only:

```go
doc, err := src.Load(ctx)
if err != nil {
	// handle load error
}

entry, ok := doc.GetByID("urn:air:acme-corp.com:mcp:weather")
mcpServers := doc.GetByType(catalog.MediaTypeMCPServerCard)
hits := doc.Search("weather")
matched, err := doc.SearchByRegex(`^urn:air:acme-corp\.com:`)
```

The same methods work on any parsed document:

```go
doc, _ := catalog.ParseFile("ai-catalog.json")

entry, ok := doc.GetByID("urn:air:acme-corp.com:mcp:weather")
agents := doc.GetByType(catalog.MediaTypeA2AAgentCard)
byTag := doc.GetByTag("finance")
byPublisher := doc.GetByPublisher("did:web:acme-corp.com")
```

### Multiple versions of an artifact

Entries may share an `identifier` and differ by `version`:

```go
all := doc.Versions("urn:air:acme.com:agent:finance")             // every version
v2, ok := doc.GetByIDAndVersion("urn:air:acme.com:agent:finance", "2.0.0")
latest, ok := doc.GetLatest("urn:air:acme.com:agent:finance")      // semver, then updatedAt
```

`GetLatest` prefers entries with a valid semantic version, compared by semver and then `updatedAt`. Without one it uses the newest `updatedAt`.

### Resolve a display name

Returns the entry's `displayName`, or else the last segment of its identifier.

```go
name := entry.ResolveDisplayName()
// "urn:air:acme-corp.com:mcp:weather" -> "weather"
```

### Validate and detect conformance level

```go
import "github.com/Agent-Card/ai-catalog-go/validate"

result := validate.Validate(doc)
if !result.IsValid {
	for _, d := range result.Errors {
		log.Printf("%s %s: %s", d.Code, d.Path, d.Message)
	}
}
log.Printf("conformance level: %s", result.ConformanceLevel) // minimal | discoverable | trusted

// Validate whatever a Source is backed by:
result, err := validate.Source(ctx, src)

// Fix the clock used for expiry, or the nesting limit (default 4):
result = validate.Validate(doc, validate.WithClock(clock), validate.WithMaxNestingDepth(2))
```

Diagnostics carry a stable `Code`; match on it rather than on the message.

`Trusted` is structural. A valid catalog with a `host` is `Trusted` when every root entry that carries `trustManifests` has at least one manifest that is a current endorsement by the entry's publisher: its `signature` uses the `did-web-v1` profile, `signature.signer` equals `contributor` and `did:web:{publisher}` for the `urn:air` identifier, the protected header has `typ` `ai-catalog-trust-manifest+jws`, `alg` `ES256` and a `kid` that is the signer plus a fragment (no `jku`, `jwk`, `x5u` or `x5c`), and `subject` and the entry's `digest` bind it to the entry. Other contributors, such as assessors, never hold an entry back, but do not make it `Trusted` alone. Profile violations and expired or not-yet-valid signatures are warnings that keep the catalog at `Discoverable`. `alg` `none` is an error. Signatures are never cryptographically verified and DID documents are not resolved.

### Trust metadata

```go
import "github.com/Agent-Card/ai-catalog-go/trust"

// Verify an attestation digest against its bytes:
ok, err := trust.VerifyDigest("sha256:9f86d0...", data)

// Canonicalize a manifest (JCS, RFC 8785) for signing or verification:
canonical, err := trust.CanonicalizeTrustManifest(&entry.TrustManifests[0])
```

A manifest read from a document is canonicalized from its original bytes, so members the SDK does not model are covered as published. A manifest built in code or changed after reading is canonicalized from its serialization; sign what `CanonicalizeTrustManifest` returns for it. `TrustManifest.Raw()` returns the original bytes.

The SDK never verifies signatures. The signing payload of a manifest or catalog is its JSON without its own `signature.jws` and `additionalSignatures`, canonicalized with JCS; nested members of those names stay in.

To verify one yourself, use the original bytes, not a re-serialized document, or unmodeled members drop out of the payload. The built-in providers keep those bytes and expose them through `catalog.RawSource`:

```go
if rawSource, ok := src.(catalog.RawSource); ok {
	raw, err := rawSource.Raw(ctx)

	// Strips the top-level "signature.jws" and "additionalSignatures" and canonicalizes the rest:
	payload, err := trust.CanonicalizeForSignature(raw)
}
```

### Package as an OCI artifact

OCI packaging is not part of the specification, so it lives in [`examples/oci`](./examples/oci):

```bash
go run ./examples/oci
```

## Development

This repository uses [Task](https://taskfile.dev):

```bash
task test   # run unit tests with race detector and coverage
task lint   # run golangci-lint
```

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md).

## License

Apache-2.0. See [LICENSE](./LICENSE).
