<!--
Copyright AGNTCY Contributors (https://github.com/agntcy)
SPDX-License-Identifier: Apache-2.0
-->

# AI Catalog Go SDK

A Go toolkit for producing, consuming, validating, and packaging [AI Catalog](https://agent-card.github.io/ai-catalog/) documents — the typed, nestable JSON format for making heterogeneous AI artifacts (MCP servers, A2A agents, datasets, model cards, nested catalogs, …) discoverable.

The SDK is a faithful implementation of the [AI Catalog specification](https://agent-card.github.io/ai-catalog/spec/).

## Installation

```bash
go get github.com/agntcy/ai-catalog-go-sdk
```

The minimum Go version is declared in [`go.mod`](./go.mod).

## Usage

### Load a catalog

The `provider` package loads a document and returns a `catalog.Source` — a read-only handle that transparently descends into nested catalogs.

```go
import (
	"context"

	"github.com/agntcy/ai-catalog-go-sdk/provider"
)

ctx := context.Background()

// From a local file:
src, err := provider.JSON(ctx, "ai-catalog.json")

// From an explicit URL:
src, err = provider.Web(ctx, "https://acme-corp.com/catalogs/finance.json")

// From a domain's well-known URI (https://acme-corp.com/.well-known/ai-catalog.json):
src, err = provider.WellKnown(ctx, "acme-corp.com")
```

Nested catalogs (inline or URL-referenced) are resolved up to `provider.DefaultMaxDepth` (4). Tune loading with options:

```go
src, err := provider.WellKnown(ctx, "acme-corp.com",
	provider.WithHTTPClient(myClient), // custom *http.Client
	provider.WithMaxDepth(2),          // shallower resolution
)
```

### Query entries

`Source` operations take a `context.Context` and search across resolved nested catalogs:

```go
entry, err := src.GetByID(ctx, "urn:air:acme-corp.com:mcp:weather")
if errors.Is(err, catalog.ErrEntryNotFound) {
	// no such entry
}

mcpServers, err := src.GetByType(ctx, "application/mcp-server-card+json")
hits, err := src.Search(ctx, "weather")
```

If you already hold a parsed `*catalog.AICatalog`, the same lookups (plus regex search) are available directly on the document, single-document and without a context:

```go
doc, _ := catalog.ParseFile("ai-catalog.json")

entry, ok := doc.GetByID("urn:air:acme-corp.com:mcp:weather")
agents := doc.GetByType("application/a2a-agent-card+json")
hits := doc.Search("weather")
matched, err := doc.SearchByRegex(`^urn:air:acme-corp\.com:`)
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
import "github.com/agntcy/ai-catalog-go-sdk/validate"

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
import "github.com/agntcy/ai-catalog-go-sdk/trust"

report := trust.AnalyzeCatalog(doc)
for _, f := range report.Findings {
	log.Printf("[%s] %s: %s", f.Severity, f.Path, f.Message)
}

// Verify an attestation digest against its bytes:
ok, err := trust.VerifyDigest("sha256:9f86d0...", data)

// Canonicalize a manifest (JCS, RFC 8785) prior to signing/verification:
canonical, err := trust.CanonicalizeTrustManifest(entry.TrustManifest)
```

### Package as an OCI artifact

```go
import "github.com/agntcy/ai-catalog-go-sdk/oci"

set, err := oci.PackCatalog(doc)           // -> *oci.ArtifactSet
err = set.ExportLayout("./layout", "v1")   // write an OCI image layout

imported, err := oci.ImportLayout("./layout", "v1")
roundTripped, err := oci.UnpackCatalog(imported)
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
