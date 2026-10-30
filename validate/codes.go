// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-go)
// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package validate

// Code is a stable identifier for a kind of diagnostic. Match on it rather than
// on the message text.
type Code string

// Catalog, host and entry rules.
const (
	CodeSpecVersion      Code = "spec-version"
	CodeHostMember       Code = "host-member-missing"
	CodeEntryMember      Code = "entry-member-missing"
	CodeEntryArtifact    Code = "entry-artifact-source"
	CodeEntryDuplicate   Code = "entry-duplicate"
	CodeEntryVersion     Code = "entry-version-conflict"
	CodeIdentifierNotURI Code = "identifier-not-uri"
	CodeTimestamp        Code = "timestamp-invalid"
	CodePublisherMember  Code = "publisher-member-missing"
	CodeExtensionKey     Code = "extension-key-invalid"
	CodeNestedDepth      Code = "nested-depth-exceeded"
	CodeNestedInvalid    Code = "nested-catalog-invalid"
	CodeDigestInvalid    Code = "digest-invalid"
	CodeEntryDigest      Code = "entry-digest-missing"
	CodePolicyURLs       Code = "policy-urls-invalid"
)

// Signature object rules.
const (
	CodeSignatureMember      Code = "signature-member-missing"
	CodeSignatureSigner      Code = "signature-signer-not-uri"
	CodeSignatureExpiry      Code = "signature-expiry-order"
	CodeSignatureForm        Code = "signature-form"
	CodeSignatureMalformed   Code = "signature-malformed"
	CodeSignatureAlgorithm   Code = "signature-algorithm-forbidden"
	CodeSignatureB64         Code = "signature-b64"
	CodeSignatureType        Code = "signature-type"
	CodeSignatureExpired     Code = "signature-expired"
	CodeSignatureNotYetValid Code = "signature-not-yet-valid"
)

// Trust manifest rules.
const (
	CodeManifestContributor    Code = "manifest-contributor-missing"
	CodeManifestContributorURI Code = "manifest-contributor-not-uri"
	CodeManifestEmpty          Code = "manifest-not-substantive"
	CodeManifestSignedMember   Code = "manifest-member-missing"
	CodeManifestSigner         Code = "manifest-signer-mismatch"
	CodeSubjectMember          Code = "subject-member-missing"
	CodeSubjectMismatch        Code = "subject-mismatch"
	CodeTrustSchemaMember      Code = "trust-schema-member-missing"
	CodeAttestationMember      Code = "attestation-member-missing"
	CodeProvenanceMember       Code = "provenance-member-missing"
)

// did:web Signer Profile rules. They are warnings that keep an entry from Trusted.
const (
	CodeProfileSigner    Code = "profile-signer"
	CodeProfileAlgorithm Code = "profile-algorithm"
	CodeProfileKeyID     Code = "profile-key-id"
	CodeProfileHeader    Code = "profile-header-member"
)
