// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package catalog

import "encoding/json"

// HostInfo identifies the operator of an AI Catalog.
type HostInfo struct {
	DisplayName string `json:"displayName,omitempty"`

	// Identifier is a verifiable host identifier (e.g. a DID or domain name).
	Identifier string `json:"identifier,omitempty"`

	DocumentationURL string `json:"documentationUrl,omitempty"`

	// LogoURL may be a data URI (RFC 2397).
	LogoURL string `json:"logoUrl,omitempty"`

	TrustManifest *TrustManifest `json:"trustManifest,omitempty"`
}

// Publisher is the canonical identity of the entity responsible for an artifact.
type Publisher struct {
	// Identifier is a verifiable identifier (e.g. a DID, domain name, or URI).
	Identifier string `json:"identifier"`

	DisplayName string `json:"displayName"`

	// IdentityType hints at Identifier's scheme (e.g. "did", "dns").
	IdentityType string `json:"identityType,omitempty"`
}

// TrustManifest provides verifiable identity, attestation, and provenance
// metadata for an artifact, sitting alongside it as a peer element.
type TrustManifest struct {
	// Identity is the subject identifier; within a CatalogEntry it must match
	// the entry's Identifier.
	Identity string `json:"identity"`

	IdentityType string           `json:"identityType,omitempty"`
	TrustSchema  *TrustSchema     `json:"trustSchema,omitempty"`
	Attestations []Attestation    `json:"attestations,omitempty"`
	Provenance   []ProvenanceLink `json:"provenance,omitempty"`

	PrivacyPolicyURL  string `json:"privacyPolicyUrl,omitempty"`
	TermsOfServiceURL string `json:"termsOfServiceUrl,omitempty"`

	// Signature is a detached JWS (RFC 7515) over the manifest, using JCS
	// (RFC 8785) canonicalization.
	Signature string `json:"signature,omitempty"`

	Metadata map[string]json.RawMessage `json:"metadata,omitempty"`
}

// TrustSchema describes the trust framework applied to an artifact.
type TrustSchema struct {
	Identifier          string   `json:"identifier"`
	Version             string   `json:"version"`
	GovernanceURI       string   `json:"governanceUri,omitempty"`
	VerificationMethods []string `json:"verificationMethods,omitempty"`
}

// Attestation is verifiable proof of a claim about an artifact (compliance
// certification, publisher identity binding, audit report, SBOM, etc.).
type Attestation struct {
	// Type is the attestation type (e.g. "SOC2-Type2", "publisher-identity").
	Type string `json:"type"`

	// URI is an HTTPS URL or Data URI locating the attestation document.
	URI string `json:"uri"`

	// Digest is an integrity digest as "algorithm:hex" (SHA-256 or stronger).
	Digest string `json:"digest,omitempty"`

	Size        *uint64 `json:"size,omitempty"`
	Description string  `json:"description,omitempty"`
}

// ProvenanceLink records lineage for an artifact.
type ProvenanceLink struct {
	// Relation to the source (e.g. "derivedFrom", "publishedFrom").
	Relation string `json:"relation"`

	// SourceID is the source artifact (e.g. a Git repo URL, OCI ref, dataset).
	SourceID string `json:"sourceId"`

	// SourceDigest is an integrity digest as "algorithm:hex".
	SourceDigest string `json:"sourceDigest,omitempty"`

	RegistryURI string `json:"registryUri,omitempty"`

	// StatementURI locates a provenance statement (e.g. in-toto / SLSA).
	StatementURI string `json:"statementUri,omitempty"`

	SignatureRef string `json:"signatureRef,omitempty"`
}
