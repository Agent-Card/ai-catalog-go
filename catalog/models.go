// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package catalog

import "encoding/json"

// HostInfo identifies the operator of an AI Catalog.
type HostInfo struct {
	// DisplayName is the human-readable name of the host (e.g. the
	// organization name).
	DisplayName string `json:"displayName,omitempty"`

	// Identifier is a verifiable identifier for the host (e.g. a DID or
	// domain name).
	Identifier string `json:"identifier,omitempty"`

	// DocumentationURL is a URL to the host's documentation.
	DocumentationURL string `json:"documentationUrl,omitempty"`

	// LogoURL is a URL to the host's logo. Data URIs (RFC 2397) are
	// recommended.
	LogoURL string `json:"logoUrl,omitempty"`

	// TrustManifest holds trust metadata for the host itself.
	TrustManifest *TrustManifest `json:"trustManifest,omitempty"`
}

// Publisher is the canonical identity of the entity responsible for an artifact.
type Publisher struct {
	// Identifier is a verifiable identifier (e.g. a DID, domain name, or URI).
	Identifier string `json:"identifier"`

	// DisplayName is the human-readable name of the publisher.
	DisplayName string `json:"displayName"`

	// IdentityType is a type hint for Identifier (e.g. "did", "dns"). It may
	// be omitted when evident.
	IdentityType string `json:"identityType,omitempty"`
}

// TrustManifest provides verifiable identity, attestation, and provenance
// metadata for an artifact. It sits alongside the artifact as a peer element
// and does not wrap or modify it.
type TrustManifest struct {
	// Identity is the primary subject identifier (DID, SPIFFE ID, or URL).
	// Within a CatalogEntry it must match the entry's Identifier.
	Identity string `json:"identity"`

	// IdentityType is a type hint for Identity (e.g. "did", "spiffe", "dns").
	IdentityType string `json:"identityType,omitempty"`

	// TrustSchema is the trust framework applied to the artifact.
	TrustSchema *TrustSchema `json:"trustSchema,omitempty"`

	// Attestations are verifiable claims (publisher identity, compliance
	// certifications, etc.).
	Attestations []Attestation `json:"attestations,omitempty"`

	// Provenance carries lineage information for the artifact.
	Provenance []ProvenanceLink `json:"provenance,omitempty"`

	// PrivacyPolicyURL is a URL to the privacy policy governing this artifact.
	PrivacyPolicyURL string `json:"privacyPolicyUrl,omitempty"`

	// TermsOfServiceURL is a URL to the terms of service.
	TermsOfServiceURL string `json:"termsOfServiceUrl,omitempty"`

	// Signature is a detached JWS (RFC 7515) signature over the manifest,
	// using JCS (RFC 8785) canonicalization.
	Signature string `json:"signature,omitempty"`

	// Metadata holds custom or vendor-specific metadata.
	Metadata map[string]json.RawMessage `json:"metadata,omitempty"`
}

// TrustSchema describes the trust framework applied to an artifact.
type TrustSchema struct {
	// Identifier of the trust schema.
	Identifier string `json:"identifier"`

	// Version of the schema.
	Version string `json:"version"`

	// GovernanceURI is a URI to the governance policy document.
	GovernanceURI string `json:"governanceUri,omitempty"`

	// VerificationMethods are the supported verification methods (e.g. "did",
	// "x509").
	VerificationMethods []string `json:"verificationMethods,omitempty"`
}

// Attestation is verifiable proof of a claim about an artifact (compliance
// certification, publisher identity binding, audit report, SBOM, etc.).
type Attestation struct {
	// Type is the attestation type (e.g. "SOC2-Type2", "ISO27001",
	// "publisher-identity").
	Type string `json:"type"`

	// URI is the location of the attestation document (HTTPS URL or Data URI).
	URI string `json:"uri"`

	// MediaType of the attestation document (e.g. "application/pdf").
	MediaType string `json:"mediaType"`

	// Digest is an integrity digest as "algorithm:hex" (SHA-256 or stronger).
	Digest string `json:"digest,omitempty"`

	// Size of the attestation document in bytes.
	Size *uint64 `json:"size,omitempty"`

	// Description is a human-readable label for the attestation.
	Description string `json:"description,omitempty"`
}

// ProvenanceLink records lineage for an artifact: its source, registry, and
// optional signed provenance statement.
type ProvenanceLink struct {
	// Relation to the source (e.g. "derivedFrom", "publishedFrom").
	Relation string `json:"relation"`

	// SourceID is the source artifact or data (e.g. a Git repo URL, OCI ref,
	// dataset URI).
	SourceID string `json:"sourceId"`

	// SourceDigest is the integrity digest of the source as "algorithm:hex".
	SourceDigest string `json:"sourceDigest,omitempty"`

	// RegistryURI is the URI of the registry holding the source.
	RegistryURI string `json:"registryUri,omitempty"`

	// StatementURI is the URI of a provenance statement (e.g. an in-toto /
	// SLSA statement).
	StatementURI string `json:"statementUri,omitempty"`

	// SignatureRef references the key used to sign the provenance statement.
	SignatureRef string `json:"signatureRef,omitempty"`
}
