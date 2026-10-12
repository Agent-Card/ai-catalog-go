// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-go)
// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package catalog

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
)

// HostInfo identifies the operator of an AI Catalog.
type HostInfo struct {
	DisplayName string `json:"displayName"`

	// Identifier is a verifiable host identifier, such as a DID or domain.
	Identifier string `json:"identifier,omitempty"`

	DocumentationURL string `json:"documentationUrl,omitempty"`

	// LogoURL may be a data URI.
	LogoURL string `json:"logoUrl,omitempty"`
}

// Publisher identifies the entity responsible for an artifact.
type Publisher struct {
	// Identifier is a verifiable identifier, such as a DID, domain or URI.
	Identifier string `json:"identifier"`

	DisplayName string `json:"displayName"`

	// IdentityType hints at the Identifier scheme, such as "did" or "dns".
	IdentityType string `json:"identityType,omitempty"`
}

// TrustManifest carries identity, attestation and provenance metadata for an artifact.
type TrustManifest struct {
	// Identity is the URI of the issuer. Under the did:web Publisher Profile it
	// is "did:web:" plus the publisher of the entry's urn:air identifier.
	Identity string `json:"identity"`

	IdentityType string           `json:"identityType,omitempty"`
	TrustSchema  *TrustSchema     `json:"trustSchema,omitempty"`
	Attestations []Attestation    `json:"attestations,omitzero"`
	Provenance   []ProvenanceLink `json:"provenance,omitzero"`

	PrivacyPolicyURL  string `json:"privacyPolicyUrl,omitempty"`
	TermsOfServiceURL string `json:"termsOfServiceUrl,omitempty"`

	// Subject binds the manifest to the artifact; required with a Signature.
	Subject *Subject `json:"subject,omitempty"`

	// IssuedAt is an RFC 3339 timestamp; required with a Signature.
	IssuedAt string `json:"issuedAt,omitempty"`

	// ExpiresAt is an RFC 3339 timestamp after which the manifest is stale.
	ExpiresAt string `json:"expiresAt,omitempty"`

	// Signature is a detached JWS over the JCS-canonicalized manifest.
	Signature string `json:"signature,omitempty"`

	// Extensions holds vendor-specific members; keys must be a URL or a
	// reverse-DNS string.
	Extensions map[string]json.RawMessage `json:"extensions,omitzero"`

	// raw is the JSON the manifest was decoded from; see Raw.
	raw json.RawMessage
}

// UnmarshalJSON decodes a manifest and keeps its source bytes, so a signature
// is checked against the document as published, not a lossy re-serialization.
func (m *TrustManifest) UnmarshalJSON(data []byte) error {
	// plain has no methods, so decoding into it does not recurse.
	type plain TrustManifest

	fresh := reflect.ValueOf(m).Elem().IsZero()

	if err := json.Unmarshal(data, (*plain)(m)); err != nil {
		return fmt.Errorf("decode trust manifest: %w", err)
	}

	// Decoding into a manifest that already holds data merges members, so the
	// bytes no longer describe it.
	if fresh && !bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		m.raw = bytes.Clone(data)
	} else {
		m.raw = nil
	}

	return nil
}

// Raw returns a copy of the JSON the manifest was decoded from, or nil if it was
// built in code. Later changes to the fields do not affect it.
func (m *TrustManifest) Raw() []byte {
	if m == nil || m.raw == nil {
		return nil
	}

	return bytes.Clone(m.raw)
}

// Subject binds a TrustManifest to the artifact it describes.
type Subject struct {
	// Identifier is the logical identifier of the bound artifact; within a
	// CatalogEntry it must equal the entry's Identifier.
	Identifier string `json:"identifier"`

	// Version is the bound release. Within a CatalogEntry it must be absent
	// when the entry has no Version, and equal to it otherwise.
	Version string `json:"version,omitempty"`

	// Type is the media type of the bound artifact; within a CatalogEntry it
	// must equal the entry's Type.
	Type string `json:"type"`

	// Digest is the artifact digest as "algorithm:hex", SHA-256 or stronger.
	Digest string `json:"digest"`

	// URL locates the artifact; within a CatalogEntry it must equal the entry's URL.
	URL string `json:"url,omitempty"`
}

// TrustSchema describes the trust framework applied to an artifact.
type TrustSchema struct {
	Identifier          string   `json:"identifier"`
	Version             string   `json:"version"`
	GovernanceURI       string   `json:"governanceUri,omitempty"`
	VerificationMethods []string `json:"verificationMethods,omitzero"`
}

// Attestation is verifiable proof of a claim about an artifact.
type Attestation struct {
	// Type is the attestation type, such as "SOC2-Type2".
	Type string `json:"type"`

	// URI is an HTTPS URL or data URI.
	URI string `json:"uri"`

	// Digest is an integrity digest as "algorithm:hex", SHA-256 or stronger.
	Digest string `json:"digest,omitempty"`

	Size        *uint64 `json:"size,omitempty"`
	Description string  `json:"description,omitempty"`
}

// ProvenanceLink records lineage for an artifact.
type ProvenanceLink struct {
	// Relation to the source, such as "derivedFrom".
	Relation string `json:"relation"`

	// SourceID identifies the source, such as a Git URL or OCI reference.
	SourceID string `json:"sourceId"`

	// SourceDigest is an integrity digest as "algorithm:hex".
	SourceDigest string `json:"sourceDigest,omitempty"`

	RegistryURI string `json:"registryUri,omitempty"`

	// StatementURI locates a provenance statement.
	StatementURI string `json:"statementUri,omitempty"`

	SignatureRef string `json:"signatureRef,omitempty"`
}
