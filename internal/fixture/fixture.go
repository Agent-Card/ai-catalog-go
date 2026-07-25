// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

// Package fixture holds a small set of AI Catalog documents shared across the
// SDK's tests, so packages do not each carry their own inline JSON. A single
// document is reused by many tests; only genuinely distinct shapes get their
// own file.
package fixture

import _ "embed"

// CatalogJSON is a comprehensive, spec-valid catalog (Trusted conformance). It
// mixes entry types, tags, publishers, multiple versions of one identifier, a
// trust manifest, and a nested catalog, and backs the parsing/query tests as
// well as the valid-nested and aligned-trust validation cases.
//
//go:embed catalog.json
var CatalogJSON []byte

// MinimalJSON is a valid, hostless catalog (Minimal conformance).
//
//go:embed minimal.json
var MinimalJSON []byte

// DiscoverableJSON is a valid catalog with a host but no trust manifest
// (Discoverable conformance).
//
//go:embed discoverable.json
var DiscoverableJSON []byte

// InvalidJSON is a single catalog that deliberately packs many independent
// validation violations (url+data, missing payload, duplicate identifier,
// duplicate versioned pair, mixed versioning, misaligned trust domain, missing
// required fields, bad updatedAt, empty metadata keys, invalid nested catalog),
// so each negative validation test can assert its own error against it. The
// "urn:dup" pair also exercises GetLatest's updatedAt fallback.
//
//go:embed invalid.json
var InvalidJSON []byte

// NestedDeepJSON nests catalogs beyond the recommended depth limit.
//
//go:embed nested_deep.json
var NestedDeepJSON []byte

// TrustFindingsJSON carries host- and entry-level trust manifests crafted to
// trigger every trust analysis finding.
//
//go:embed trust_findings.json
var TrustFindingsJSON []byte

// TrustNonURIJSON has an entry trust manifest with a non-URI identity.
//
//go:embed trust_nonuri.json
var TrustNonURIJSON []byte

// TrustCleanJSON is a well-formed trusted catalog that yields no findings; its
// entry manifest also carries a signature and unsorted metadata for the
// canonicalization test.
//
//go:embed trust_clean.json
var TrustCleanJSON []byte
