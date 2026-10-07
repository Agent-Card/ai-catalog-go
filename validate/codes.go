// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-go)
// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package validate

// Code is a stable identifier for a kind of diagnostic. Match on it rather than
// on the message text.
type Code string

// Catalog, host and entry rules.
const (
	CodeSpecVersion        Code = "spec-version"
	CodeHostMember         Code = "host-member-missing"
	CodeEntryMember        Code = "entry-member-missing"
	CodeEntryArtifact      Code = "entry-artifact-source"
	CodeEntryDuplicate     Code = "entry-duplicate"
	CodeEntryVersion       Code = "entry-version-conflict"
	CodeIdentifierNotURI   Code = "identifier-not-uri"
	CodeTimestamp          Code = "timestamp-invalid"
	CodePublisherMember    Code = "publisher-member-missing"
	CodeExtensionKey       Code = "extension-key-invalid"
	CodeNestedDepth        Code = "nested-depth-exceeded"
	CodeNestedInvalid      Code = "nested-catalog-invalid"
	CodeDigestInvalid      Code = "digest-invalid"
	CodeSignatureForm      Code = "signature-form"
	CodeSignatureMalformed Code = "signature-malformed"
	CodeSignatureAlgorithm Code = "signature-algorithm-forbidden"
	CodeSignatureB64       Code = "signature-b64"
	CodeSignatureUnlisted  Code = "signature-algorithm-unlisted"
)

// Trust manifest rules.
const (
	CodeManifestIdentity     Code = "manifest-identity-missing"
	CodeManifestIdentityURI  Code = "manifest-identity-not-uri"
	CodeManifestEmpty        Code = "manifest-not-substantive"
	CodeManifestSignedMember Code = "manifest-member-missing"
	CodeManifestExpired      Code = "manifest-expired"
	CodeSubjectMember        Code = "subject-member-missing"
	CodeSubjectMismatch      Code = "subject-mismatch"
	CodeTrustSchemaMember    Code = "trust-schema-member-missing"
	CodeAttestationMember    Code = "attestation-member-missing"
	CodeProvenanceMember     Code = "provenance-member-missing"
)

// did:web Publisher Profile rules. They are warnings: a manifest that breaks
// one is still a well-formed document, but the catalog cannot be Trusted.
const (
	CodeProfileIdentifier Code = "profile-identifier"
	CodeProfileIdentity   Code = "profile-identity"
	CodeProfileType       Code = "profile-identity-type"
	CodeProfileAlgorithm  Code = "profile-algorithm"
	CodeProfileKeyID      Code = "profile-key-id"
	CodeProfileHeader     Code = "profile-header-member"
)
