// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-go)
// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

// Package fixture holds the AI Catalog documents shared across the SDK's tests.
package fixture

import _ "embed"

// CatalogJSON is the comprehensive fixture: Trusted conformance, mixed entry
// types, multiple versions of one identifier, and a nested catalog.
//
//go:embed catalog.json
var CatalogJSON []byte

//go:embed minimal.json
var MinimalJSON []byte

//go:embed discoverable.json
var DiscoverableJSON []byte

// InvalidJSON packs one instance of every validation violation the SDK reports.
//
//go:embed invalid.json
var InvalidJSON []byte

// NestedMaxJSON nests exactly to the depth limit; NestedDeepJSON one beyond it.
//
//go:embed nested_max.json
var NestedMaxJSON []byte

//go:embed nested_deep.json
var NestedDeepJSON []byte

//go:embed unsigned_trust.json
var UnsignedTrustJSON []byte

// TrustFindingsJSON triggers every trust analysis finding.
//
//go:embed trust_findings.json
var TrustFindingsJSON []byte

//go:embed trust_nonuri.json
var TrustNonURIJSON []byte

// UnboundIdentityJSON has an entry identity carrying no trust domain to bind.
//
//go:embed unbound_identity.json
var UnboundIdentityJSON []byte

// TrustCleanJSON is trusted and yields no findings; its manifest carries
// unsorted extensions for the canonicalization test.
//
//go:embed trust_clean.json
var TrustCleanJSON []byte

//go:embed weak_signature.json
var WeakSignatureJSON []byte
