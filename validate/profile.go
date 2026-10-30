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

// didWebProfile is the reserved name of the did:web Signer Profile.
const didWebProfile = "did-web-v1"

// profileAlgorithm is the only algorithm the did:web Signer Profile accepts.
const profileAlgorithm = "ES256"

// keySourceMembers are protected header members through which a signature
// would name its own key; the profile takes keys from the DID document only.
var keySourceMembers = []string{"jku", "jwk", "x5u", "x5c"}

// checkSignerProfile applies the did:web Signer Profile to a signature that
// selects it, adds a warning for each violation, and reports whether there
// were none.
func (v *validator) checkSignerProfile(signature *catalog.Signature, header jws.Header, path string) bool {
	before := len(v.warnings)

	if !identity.RootDIDWeb(signature.Signer) {
		v.addWarning(CodeProfileSigner, path+".signer", fmt.Sprintf(
			"signer %q must be a root did:web DID with a lowercase ASCII domain and no port, path or IP",
			signature.Signer))
	}

	if header.Algorithm != profileAlgorithm && !jws.Forbidden(header.Algorithm) {
		v.addWarning(CodeProfileAlgorithm, path+".jws", fmt.Sprintf(
			"jws algorithm %q must be %s", header.Algorithm, profileAlgorithm))
	}

	fragment, ok := strings.CutPrefix(header.KeyID, signature.Signer+"#")
	if !ok || fragment == "" || strings.ContainsAny(fragment, "/?#") {
		v.addWarning(CodeProfileKeyID, path+".jws", fmt.Sprintf(
			"jws kid %q must be the signer %q followed by a fragment", header.KeyID, signature.Signer))
	}

	for _, member := range keySourceMembers {
		if header.Has(member) {
			v.addWarning(CodeProfileHeader, path+".jws", fmt.Sprintf(
				"jws header must not contain '%s'", member))
		}
	}

	return len(v.warnings) == before
}

// isPublisher reports whether signer is the did:web DID of the publisher in the
// entry's urn:air identifier.
func isPublisher(entry *catalog.CatalogEntry, signer string) bool {
	publisher, ok := identity.Publisher(entry.Identifier)

	return ok && identity.ValidPublisher(publisher) && signer == identity.DID(publisher)
}
