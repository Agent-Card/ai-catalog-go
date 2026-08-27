<!--
Copyright AI-Catalog Contributors (https://github.com/Agent-Card)
SPDX-License-Identifier: Apache-2.0
-->

# AI Catalog Go SDK

A Go toolkit for consuming, validating, and analyzing [AI Catalog](https://ai-catalog.io/) documents — the typed, nestable JSON format for making heterogeneous AI artifacts (MCP servers, A2A agents, datasets, model cards, nested catalogs, …) discoverable.

The SDK is a faithful implementation of the [AI Catalog specification](https://ai-catalog.io/spec/).

## Scope

The repository follows the AI Catalog spec's own split between **normative** content (defines the format and conformance) and **non-normative** content (informative or convenience code):

- **Normative** — a faithful implementation of the spec and the stable, supported API: the document/entry types, parsing, and querying (`catalog`); conformance validation (`validate`); and trust-manifest analysis and canonicalization (`trust`). For convenience, `catalog` also adds lookups the spec does not require (e.g. `GetByTag`, `GetByPublisher`, `SearchByRegex`) on the spec-defined types.
- **Non-normative** — code the spec does not define:
  - `provider` (and the `catalog.Source` interface) — a supported convenience for loading a catalog from a local file or an HTTP endpoint.
  - [`examples/`](./examples) — informative, spec-adjacent samples such as packaging a catalog as an OCI artifact (the spec only describes an informative "mapping to OCI"). Reference code to copy and adapt, not part of the supported API.

## Installation

```bash
go get github.com/Agent-Card/ai-catalog-go
```

The minimum Go version is declared in [`go.mod`](./go.mod).

## Usage

### Load a catalog

The `provider` package returns a `catalog.Source` — a loader for an AI Catalog. Each built-in loads the document as-is (nested catalog entries are left unresolved for the caller to follow as needed).

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

`Web` retrieves documents over HTTP; supply a custom client with `provider.WithHTTPClient(myClient)` or an entirely custom transport with `provider.WithFetcher(...)`.

If you already hold a parsed `*catalog.AICatalog`, you don't need a `Source` — call its methods directly (see below).

### Query entries

`Source` has a single method, `Load`, which returns the whole catalog in memory as a `*catalog.AICatalog`. Query it with the document's methods, which cover the entries of that document — follow any nested catalog entry yourself to query its contents:

```go
doc, err := src.Load(ctx)
if err != nil {
	// handle load error
}

entry, ok := doc.GetByID("urn:air:acme-corp.com:mcp:weather")
mcpServers := doc.GetByType("application/mcp-server-card+json")
hits := doc.Search("weather")
matched, err := doc.SearchByRegex(`^urn:air:acme-corp\.com:`)
```

The same methods are available on any parsed document, so a `Source` is not required:

```go
doc, _ := catalog.ParseFile("ai-catalog.json")

entry, ok := doc.GetByID("urn:air:acme-corp.com:mcp:weather")
agents := doc.GetByType("application/a2a-agent-card+json")
byTag := doc.GetByTag("finance")
byPublisher := doc.GetByPublisher("did:web:acme-corp.com")
```

### Multiple versions of an artifact

A catalog may list several entries with the same `identifier` and different `version` values. The SDK selects among them per the spec:

```go
all := doc.Versions("urn:air:acme.com:agent:finance")             // every version
v2, ok := doc.GetByIDAndVersion("urn:air:acme.com:agent:finance", "2.0.0")
latest, ok := doc.GetLatest("urn:air:acme.com:agent:finance")      // semver, then updatedAt
```

`GetLatest` prefers entries whose `version` parses as a Semantic Version (compared with `golang.org/x/mod/semver`, ties broken by the more recent `updatedAt`), falling back to the newest `updatedAt` when no version is parseable.

### Resolve a display name

Follows the spec's resolution order for the steps that don't require fetching the artifact: the entry's `displayName`, otherwise the trailing segment of its identifier.

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
		log.Printf("%s: %s", d.Path, d.Message)
	}
}
log.Printf("conformance level: %s", result.ConformanceLevel) // minimal | discoverable | trusted

// Validate whatever a Source is backed by:
result, err := validate.Source(ctx, src)
```

### Analyze trust metadata

```go
import "github.com/Agent-Card/ai-catalog-go/trust"

report := trust.AnalyzeCatalog(doc)
for _, f := range report.Findings {
	log.Printf("[%s] %s: %s", f.Severity, f.Path, f.Message)
}

// Verify an attestation digest against its bytes:
ok, err := trust.VerifyDigest("sha256:9f86d0...", data)

// Canonicalize a manifest (JCS, RFC 8785) prior to signing/verification:
canonical, err := trust.CanonicalizeTrustManifest(entry.TrustManifest)
```

A signature covers the document as published, so verify against the original bytes rather than a re-serialized document — otherwise any member this SDK does not model drops out of the payload and the signature will not match. The built-in providers keep those bytes and expose them through `catalog.RawSource`:

```go
if rawSource, ok := src.(catalog.RawSource); ok {
	raw, err := rawSource.Raw(ctx)

	// Strips the top-level "signature" and canonicalizes the rest:
	payload, err := trust.CanonicalizeForSignature(raw)
}
```

### Package as an OCI artifact

Mapping a catalog onto OCI is not part of the specification, so it lives in [`examples/oci`](./examples/oci) rather than the SDK. Run it with:

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
