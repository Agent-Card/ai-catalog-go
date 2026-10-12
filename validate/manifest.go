// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-go)
// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package validate

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/Agent-Card/ai-catalog-go/catalog"
	"github.com/Agent-Card/ai-catalog-go/internal/jws"
	"github.com/Agent-Card/ai-catalog-go/trust"
)

// allowedJWSAlgorithms is the specification's signature algorithm allowlist.
var allowedJWSAlgorithms = []string{"ES256", "ES384", "EdDSA", "PS256", "PS384", "RS256"}

func (v *validator) validateEntryTrust(entry *catalog.CatalogEntry, path string, depth int) {
	manifest := entry.TrustManifest
	if manifest == nil {
		return
	}

	path += ".trustManifest"

	v.validateTrustManifest(manifest, path)
	v.validateSubjectBinding(entry, path)

	ready := isSigned(manifest) && v.checkProfile(entry, path) && !v.expired(manifest)

	if depth == 0 {
		v.manifests++
		v.heldBack = v.heldBack || !ready
	}
}

// isSigned reports whether the manifest carries a signature with its subject
// and issuedAt.
func isSigned(manifest *catalog.TrustManifest) bool {
	return manifest.Signature != "" && manifest.Subject != nil && manifest.IssuedAt != ""
}

// validateTrustManifest checks the rules that hold for a trust manifest.
func (v *validator) validateTrustManifest(manifest *catalog.TrustManifest, path string) {
	v.validateExtensionKeys(manifest.Extensions, path+".extensions")
	v.validateIdentity(manifest.Identity, path+".identity")

	// An empty manifest must be omitted.
	if !isSubstantive(manifest) {
		v.addError(CodeManifestEmpty, path, "trustManifest must carry at least one substantive member "+
			"(a signature with its subject and issuedAt, a non-empty attestations or "+
			"provenance array, or a trustSchema) and must otherwise be omitted entirely")
	}

	v.validateSignedMembers(manifest, path)
	v.validateSignature(manifest.Signature, path+".signature")
	v.validateTimestamp(manifest.IssuedAt, path+".issuedAt")
	v.validateExpiry(manifest, path)
	v.validateSubject(manifest.Subject, path+".subject")
	v.validateTrustSchema(manifest.TrustSchema, path+".trustSchema")
	v.validateAttestations(manifest.Attestations, path)
	v.validateProvenance(manifest.Provenance, path)
}

func (v *validator) validateIdentity(identity, path string) {
	switch {
	case identity == "":
		v.addError(CodeManifestIdentity, path, "trustManifest.identity is required and must not be empty")
	case !strings.Contains(identity, ":"):
		v.addWarning(CodeManifestIdentityURI, path, "trustManifest.identity SHOULD be a URI")
	}
}

// isSubstantive reports whether a manifest carries verifiable trust evidence. A
// subject and issuedAt count only alongside a signature.
func isSubstantive(manifest *catalog.TrustManifest) bool {
	return isSigned(manifest) ||
		len(manifest.Attestations) > 0 ||
		len(manifest.Provenance) > 0 ||
		manifest.TrustSchema != nil
}

// validateSignedMembers requires the members a signature must cover, so it cannot be replayed.
func (v *validator) validateSignedMembers(manifest *catalog.TrustManifest, path string) {
	if manifest.Signature == "" {
		return
	}

	if manifest.Subject == nil {
		v.addError(CodeManifestSignedMember, path+".subject",
			"a trustManifest carrying a signature must include a subject")
	}

	if manifest.IssuedAt == "" {
		v.addError(CodeManifestSignedMember, path+".issuedAt",
			"a trustManifest carrying a signature must include issuedAt")
	}
}

// expired reports whether the manifest's expiresAt is in the past.
func (v *validator) expired(manifest *catalog.TrustManifest) bool {
	expiresAt, err := time.Parse(time.RFC3339, manifest.ExpiresAt)

	return err == nil && expiresAt.Before(v.cfg.now())
}

func (v *validator) validateExpiry(manifest *catalog.TrustManifest, path string) {
	v.validateTimestamp(manifest.ExpiresAt, path+".expiresAt")

	if v.expired(manifest) {
		v.addWarning(CodeManifestExpired, path+".expiresAt", fmt.Sprintf(
			"trustManifest expired at %q and SHOULD be rejected", manifest.ExpiresAt))
	}
}

func (v *validator) validateSubject(subject *catalog.Subject, path string) {
	if subject == nil {
		return
	}

	required := []struct{ member, value string }{
		{"identifier", subject.Identifier},
		{"type", subject.Type},
		{"digest", subject.Digest},
	}

	for _, r := range required {
		if r.value == "" {
			v.addError(CodeSubjectMember, path+"."+r.member,
				fmt.Sprintf("subject.%s is required and must not be empty", r.member))
		}
	}

	v.validateDigest(subject.Digest, path+".digest")
}

// validateSubjectBinding requires the subject to restate the entry's
// identifier, version, type and url, which brings them into the signed payload.
func (v *validator) validateSubjectBinding(entry *catalog.CatalogEntry, path string) {
	subject := entry.TrustManifest.Subject
	if subject == nil {
		return
	}

	if subject.Identifier != "" && subject.Identifier != entry.Identifier {
		v.addError(CodeSubjectMismatch, path+".subject.identifier", fmt.Sprintf(
			"subject.identifier %q must equal the entry identifier %q", subject.Identifier, entry.Identifier))
	}

	if subject.Version != entry.Version {
		v.addError(CodeSubjectMismatch, path+".subject.version", fmt.Sprintf(
			"subject.version %q must equal the entry version %q (both absent or both present)",
			subject.Version, entry.Version))
	}

	if subject.Type != "" && entry.Type != "" && subject.Type != entry.Type {
		v.addError(CodeSubjectMismatch, path+".subject.type", fmt.Sprintf(
			"subject.type %q must equal the entry type %q", subject.Type, entry.Type))
	}

	if subject.URL != "" && subject.URL != entry.URL {
		v.addError(CodeSubjectMismatch, path+".subject.url", fmt.Sprintf(
			"subject.url %q must equal the entry url %q", subject.URL, entry.URL))
	}
}

func (v *validator) validateTrustSchema(schema *catalog.TrustSchema, path string) {
	if schema == nil {
		return
	}

	if schema.Identifier == "" {
		v.addError(CodeTrustSchemaMember, path+".identifier", "trustSchema.identifier must not be empty")
	}

	if schema.Version == "" {
		v.addError(CodeTrustSchemaMember, path+".version", "trustSchema.version must not be empty")
	}
}

func (v *validator) validateAttestations(attestations []catalog.Attestation, path string) {
	for i := range attestations {
		attestation := &attestations[i]
		base := fmt.Sprintf("%s.attestations[%d]", path, i)

		if attestation.Type == "" {
			v.addError(CodeAttestationMember, base+".type", "attestation type must not be empty")
		}

		if attestation.URI == "" {
			v.addError(CodeAttestationMember, base+".uri", "attestation uri must not be empty")
		}

		v.validateDigest(attestation.Digest, base+".digest")
	}
}

func (v *validator) validateProvenance(provenance []catalog.ProvenanceLink, path string) {
	for i := range provenance {
		link := &provenance[i]
		base := fmt.Sprintf("%s.provenance[%d]", path, i)

		if link.Relation == "" {
			v.addError(CodeProvenanceMember, base+".relation", "provenance relation must not be empty")
		}

		if link.SourceID == "" {
			v.addError(CodeProvenanceMember, base+".sourceId", "provenance sourceId must not be empty")
		}

		v.validateDigest(link.SourceDigest, base+".sourceDigest")
	}
}

// validateDigest rejects a present digest that is malformed or weaker than
// SHA-256.
func (v *validator) validateDigest(value, path string) {
	if value == "" {
		return
	}

	if _, err := trust.ParseDigest(value); err != nil {
		v.addError(CodeDigestInvalid, path, err.Error())
	}
}

// validateSignature applies the rules shared by catalog and trust manifest
// signatures. "none" and the HMAC family cannot establish third-party trust.
func (v *validator) validateSignature(signature, path string) {
	if signature == "" {
		return
	}

	if !jws.Detached(signature) {
		v.addError(CodeSignatureForm, path, "signature must use detached JWS compact serialization")

		return
	}

	result := jws.Check(signature)

	switch result.Problem {
	case jws.Malformed:
		v.addError(CodeSignatureMalformed, path, result.Message)

		return
	case jws.Forbidden:
		v.addError(CodeSignatureAlgorithm, path, result.Message)

		return
	case jws.OK:
	}

	if header, err := jws.Parse(signature); err == nil && header.Has("b64") {
		v.addError(CodeSignatureB64, path, "signature header must not contain 'b64'")
	}

	if !slices.Contains(allowedJWSAlgorithms, result.Algorithm) {
		v.addWarning(CodeSignatureUnlisted, path, fmt.Sprintf(
			"signature algorithm '%s' is outside the specification allowlist (%s)",
			result.Algorithm, strings.Join(allowedJWSAlgorithms, ", ")))
	}
}
