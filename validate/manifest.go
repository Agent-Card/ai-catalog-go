// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-go)
// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package validate

import (
	"fmt"

	"github.com/Agent-Card/ai-catalog-go/catalog"
	"github.com/Agent-Card/ai-catalog-go/internal/jws"
	"github.com/Agent-Card/ai-catalog-go/trust"
)

func (v *validator) validateEntryTrust(entry *catalog.CatalogEntry, path string, depth int) {
	v.validateDigest(entry.Digest, path+".digest")

	var hasSigned, hasPublisher bool

	for i := range entry.TrustManifests {
		manifest := &entry.TrustManifests[i]
		manifestPath := fmt.Sprintf("%s.trustManifests[%d]", path, i)

		v.validateTrustManifest(manifest, manifestPath)

		hasSigned = hasSigned || manifest.Signature != nil

		bound := v.validateSubjectBinding(entry, manifest, manifestPath)
		endorsed := v.isPublisherEndorsement(entry, manifest, manifestPath)

		hasPublisher = hasPublisher || (bound && endorsed)
	}

	if hasSigned && entry.Digest == "" {
		v.addError(CodeEntryDigest, path+".digest",
			"an entry carrying a signed trust manifest must include digest")

		hasPublisher = false
	}

	if depth == 0 && len(entry.TrustManifests) > 0 {
		v.entriesWithManifests++
		v.heldBack = v.heldBack || !hasPublisher
	}
}

// validateTrustManifest checks the rules that hold for a trust manifest.
func (v *validator) validateTrustManifest(manifest *catalog.TrustManifest, path string) {
	v.validateExtensionKeys(manifest.Extensions, path+".extensions")
	v.validateContributor(manifest.Contributor, path+".contributor")

	// An empty manifest must be omitted.
	if !isSubstantive(manifest) {
		v.addError(CodeManifestEmpty, path, "trust manifest must contain at least one of a signature, "+
			"a trustSchema, non-empty attestations or provenance, or non-empty extensions, "+
			"and must otherwise be omitted entirely")
	}

	if signature := manifest.Signature; signature != nil {
		signaturePath := path + ".signature"

		if manifest.Subject == nil {
			v.addError(CodeManifestSignedMember, path+".subject",
				"a trust manifest carrying a signature must include a subject")
		}

		v.validateSignature(signature, manifestJWSType, signaturePath)

		if signature.Signer != "" && signature.Signer != manifest.Contributor {
			v.addError(CodeManifestSigner, signaturePath+".signer", fmt.Sprintf(
				"signature.signer %q must exactly equal the contributor %q", signature.Signer, manifest.Contributor))
		}
	}

	v.validateSubject(manifest.Subject, path+".subject")
	v.validateTrustSchema(manifest.TrustSchema, path+".trustSchema")
	v.validateAttestations(manifest.Attestations, path)
	v.validateProvenance(manifest.Provenance, path)
}

func (v *validator) validateContributor(contributor, path string) {
	switch {
	case contributor == "":
		v.addError(CodeManifestContributor, path, "trust manifest contributor is required and must not be empty")
	case !isAbsoluteURI(contributor):
		v.addError(CodeManifestContributorURI, path, "trust manifest contributor must be an absolute URI")
	}
}

// isSubstantive reports whether a manifest carries trust evidence.
func isSubstantive(manifest *catalog.TrustManifest) bool {
	return manifest.Signature != nil ||
		manifest.TrustSchema != nil ||
		len(manifest.Attestations) > 0 ||
		len(manifest.Provenance) > 0 ||
		len(manifest.Extensions) > 0
}

// isPublisherEndorsement reports whether the manifest is a signed, current
// did:web endorsement of the entry by the publisher its urn:air identifier
// names, free of profile violations.
func (v *validator) isPublisherEndorsement(entry *catalog.CatalogEntry, manifest *catalog.TrustManifest, path string) bool {
	signature := manifest.Signature
	if signature == nil {
		return false
	}

	// Parse quietly: the structure was already reported while validating the manifest.
	header, err := jws.Parse(signature.JWS)
	if err != nil || signature.Profile != didWebProfile || !jws.Detached(signature.JWS) {
		return false
	}

	signaturePath := path + ".signature"
	profileOK := v.checkSignerProfile(signature, header, signaturePath)
	current := v.signatureCurrent(signature, signaturePath)

	return profileOK && current &&
		signature.Signer == manifest.Contributor &&
		header.Type == manifestJWSType &&
		isPublisher(entry, signature.Signer)
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
// identifier, type, digest and version, and reports whether it does.
func (v *validator) validateSubjectBinding(entry *catalog.CatalogEntry, manifest *catalog.TrustManifest, path string) bool {
	subject := manifest.Subject
	if subject == nil {
		return false
	}

	before := len(v.errors)

	if subject.Identifier != "" && subject.Identifier != entry.Identifier {
		v.addError(CodeSubjectMismatch, path+".subject.identifier", fmt.Sprintf(
			"subject.identifier %q must equal the entry identifier %q", subject.Identifier, entry.Identifier))
	}

	if subject.Type != "" && entry.Type != "" && subject.Type != entry.Type {
		v.addError(CodeSubjectMismatch, path+".subject.type", fmt.Sprintf(
			"subject.type %q must equal the entry type %q", subject.Type, entry.Type))
	}

	if subject.Digest != "" && entry.Digest != "" && subject.Digest != entry.Digest {
		v.addError(CodeSubjectMismatch, path+".subject.digest", fmt.Sprintf(
			"subject.digest %q must equal the entry digest %q", subject.Digest, entry.Digest))
	}

	if subject.Version != entry.Version {
		v.addError(CodeSubjectMismatch, path+".subject.version", fmt.Sprintf(
			"subject.version %q must be present exactly when the entry version is and equal it (%q)",
			subject.Version, entry.Version))
	}

	return len(v.errors) == before
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
