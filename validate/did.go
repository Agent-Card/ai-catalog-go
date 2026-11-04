// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-go)
// SPDX-License-Identifier: Apache-2.0

package validate

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Agent-Card/ai-catalog-go/internal/identity"
)

const didWebPrefix = "did:web:"

// didDocumentURL returns the DID document URL of a root did:web DID.
func didDocumentURL(did string) (string, bool) {
	domain, ok := strings.CutPrefix(did, didWebPrefix)
	if !ok || !identity.RootDIDWeb(did) {
		return "", false
	}

	return "https://" + domain + "/.well-known/did.json", true
}

type verificationMethod struct {
	ID           string          `json:"id"`
	Controller   string          `json:"controller"`
	PublicKeyJWK json.RawMessage `json:"publicKeyJwk"`
}

type didDocument struct {
	ID                 string               `json:"id"`
	VerificationMethod []verificationMethod `json:"verificationMethod"`
	AssertionMethod    []json.RawMessage    `json:"assertionMethod"`
}

// methodsOf returns the verification methods that kid selects, and whether
// assertionMethod authorizes kid.
func (d *didDocument) methodsOf(signer, kid string) ([]verificationMethod, bool) {
	resolve := func(reference string) string {
		if strings.HasPrefix(reference, "#") {
			return signer + reference
		}

		return reference
	}

	var methods []verificationMethod

	for _, method := range d.VerificationMethod {
		if resolve(method.ID) == kid {
			methods = append(methods, method)
		}
	}

	authorized := false

	for _, raw := range d.AssertionMethod {
		var reference string

		if json.Unmarshal(raw, &reference) == nil {
			authorized = authorized || resolve(reference) == kid

			continue
		}

		var embedded verificationMethod

		if json.Unmarshal(raw, &embedded) == nil && resolve(embedded.ID) == kid {
			authorized = true

			methods = append(methods, embedded)
		}
	}

	return methods, authorized
}

// selectKey returns the JWK of kid: a single method, authorized by
// assertionMethod, controlled by signer.
func selectKey(document []byte, signer, kid string) ([]byte, error) {
	var parsed didDocument
	if err := json.Unmarshal(document, &parsed); err != nil {
		return nil, fmt.Errorf("the DID document is not valid: %w", err)
	}

	if parsed.ID != signer {
		return nil, fmt.Errorf("the DID document id is not %q", signer)
	}

	methods, authorized := parsed.methodsOf(signer, kid)
	if !authorized {
		return nil, fmt.Errorf("assertionMethod does not authorize %q", kid)
	}

	if len(methods) != 1 {
		return nil, fmt.Errorf("%q selects %d verification methods, not one", kid, len(methods))
	}

	if methods[0].Controller != signer {
		return nil, fmt.Errorf("the controller of %q is not %q", kid, signer)
	}

	if len(methods[0].PublicKeyJWK) == 0 || string(methods[0].PublicKeyJWK) == "null" {
		return nil, fmt.Errorf("%q has no publicKeyJwk", kid)
	}

	return methods[0].PublicKeyJWK, nil
}
