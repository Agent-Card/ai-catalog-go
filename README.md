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

- **Normative**: the stable, supported API. Document types, parsing and querying (`catalog`), conformance validation (`validate`), and digest verification and canonicalization (`trust`). `catalog` also has lookups the spec does not define, such as `GetByTag`, `GetByPublisher` and `SearchByRegex`.
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

`Trusted` is structural. Every root entry's trust manifest must be signed, bound to its entry by `subject`, unexpired, and conform to the `did:web` Publisher Profile: a `urn:air` identifier, identity exactly `did:web:{publisher}`, an ES256 signature whose `kid` is the identity plus a fragment, and no `jku`, `jwk`, `x5u` or `x5c`. Profile violations are warnings that keep the catalog at `Discoverable`. Signatures are not verified and DID documents are not resolved.

### Trust metadata

```go
import "github.com/Agent-Card/ai-catalog-go/trust"

// Verify an attestation digest against its bytes:
ok, err := trust.VerifyDigest("sha256:9f86d0...", data)

// Canonicalize a manifest (JCS, RFC 8785) for signing or verification:
canonical, err := trust.CanonicalizeTrustManifest(entry.TrustManifest)
```

A manifest read from a document is canonicalized from its original bytes, so members the SDK does not model are covered as published. A manifest built in code or changed after reading is canonicalized from its serialization; sign what `CanonicalizeTrustManifest` returns for it. `TrustManifest.Raw()` returns the original bytes.

Verify signatures against the original bytes, not a re-serialized document, or unmodeled members drop out of the payload. The built-in providers keep those bytes and expose them through `catalog.RawSource`:

```go
if rawSource, ok := src.(catalog.RawSource); ok {
	raw, err := rawSource.Raw(ctx)

	// Strips the top-level "signature" and canonicalizes the rest:
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
