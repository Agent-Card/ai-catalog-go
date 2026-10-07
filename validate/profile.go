// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-go)
// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package validate

import (
	"fmt"
	"strings"

	"github.com/Agent-Card/ai-catalog-go/catalog"
	"github.com/Agent-Card/ai-catalog-go/internal/identity"
	"github.com/Agent-Card/ai-catalog-go/internal/jws"
)

// profileAlgorithm is the only algorithm the did:web Publisher Profile accepts.
const profileAlgorithm = "ES256"

// keySourceMembers are protected header members through which a signature
// would name its own key; the profile takes keys from the DID document only.
var keySourceMembers = []string{"jku", "jwk", "x5u", "x5c"}

// checkProfile applies the did:web Publisher Profile to a signed entry trust
// manifest, adds a warning for each violation, and reports whether there were
// none. A manifest without a usable signature is reported elsewhere and fails
// the check.
func (v *validator) checkProfile(entry *catalog.CatalogEntry, path string) bool {
	manifest := entry.TrustManifest

	header, err := jws.Parse(manifest.Signature)
	if err != nil || !jws.Detached(manifest.Signature) {
		return false
	}

	before := len(v.warnings)

	v.checkNamespace(entry, path)
	v.checkHeader(manifest, header, path+".signature")

	return len(v.warnings) == before
}

// checkNamespace checks that the issuer is the did:web DID of the publisher in
// the entry's urn:air identifier.
func (v *validator) checkNamespace(entry *catalog.CatalogEntry, path string) {
	manifest := entry.TrustManifest

	publisher, ok := identity.Publisher(entry.Identifier)
	if !ok || !identity.ValidPublisher(publisher) {
		v.addWarning(CodeProfileIdentifier, path, fmt.Sprintf(
			"entry identifier %q must start with the lowercase prefix \"urn:air:\" followed by a lowercase DNS publisher",
			entry.Identifier))
	} else if want := identity.DID(publisher); manifest.Identity != want {
		v.addWarning(CodeProfileIdentity, path+".identity", fmt.Sprintf(
			"trustManifest.identity %q must be exactly %q", manifest.Identity, want))
	}

	if manifest.IdentityType != "" && manifest.IdentityType != "did" {
		v.addWarning(CodeProfileType, path+".identityType", fmt.Sprintf(
			"trustManifest.identityType %q must be \"did\"", manifest.IdentityType))
	}
}

// checkHeader checks the algorithm, key id and key-source members of the
// protected header.
func (v *validator) checkHeader(manifest *catalog.TrustManifest, header jws.Header, path string) {
	if header.Algorithm != profileAlgorithm && jws.Check(manifest.Signature).Problem == jws.OK {
		v.addWarning(CodeProfileAlgorithm, path, fmt.Sprintf(
			"signature algorithm %q must be %s", header.Algorithm, profileAlgorithm))
	}

	if fragment, ok := strings.CutPrefix(header.KeyID, manifest.Identity+"#"); !ok || fragment == "" {
		v.addWarning(CodeProfileKeyID, path, fmt.Sprintf(
			"signature kid %q must be the identity %q followed by a fragment", header.KeyID, manifest.Identity))
	}

	for _, member := range keySourceMembers {
		if header.Has(member) {
			v.addWarning(CodeProfileHeader, path, fmt.Sprintf(
				"signature header must not contain '%s'", member))
		}
	}
}
