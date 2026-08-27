// Copyright AI-Catalog Contributors (https://github.com/Agent-Card)
// SPDX-License-Identifier: Apache-2.0

package trust

import (
	"encoding/json"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/Agent-Card/ai-catalog-go/catalog"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

// ErrUncanonicalizableJSON indicates input that cannot be canonicalized, such as
// a number outside the IEEE 754 double range, a duplicate member name, or
// trailing content after the top-level value.
var ErrUncanonicalizableJSON = errors.New("JSON cannot be canonicalized")

// signatureMember is the member excluded from a canonical signing payload: a
// detached signature cannot cover itself.
const signatureMember = "signature"

// Canonicalize returns the JCS (RFC 8785) canonical form of a JSON object or
// array: members sorted by UTF-16 code unit, minimal string escaping, and
// ECMAScript number formatting.
//
// Input that is not I-JSON (RFC 7493) is rejected. Duplicate member names, lone
// surrogates, and invalid UTF-8 all canonicalize ambiguously, so signing them
// would let a producer and a verifier commit to different documents.
func Canonicalize(data []byte) ([]byte, error) {
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("%w: input is not valid UTF-8", ErrUncanonicalizableJSON)
	}

	// The canonicalizer tolerates a few malformed number literals, such as the
	// leading zero in "01", that RFC 8259 forbids outright.
	if !json.Valid(data) {
		return nil, fmt.Errorf("%w: input is not well-formed JSON", ErrUncanonicalizableJSON)
	}

	canonical, err := jsoncanonicalizer.Transform(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUncanonicalizableJSON, err)
	}

	return canonical, nil
}

// CanonicalizeForSignature returns the JCS (RFC 8785) canonical form of a JSON
// document with its top-level "signature" member removed, producing the payload
// that a detached JWS signs and verifies against. Because it works on the
// original bytes it also covers members this SDK does not model.
func CanonicalizeForSignature(data []byte) ([]byte, error) {
	// Canonicalize first: it rejects duplicate member names, which the
	// round-trip below would otherwise collapse into whichever one
	// encoding/json happens to keep.
	canonical, err := Canonicalize(data)
	if err != nil {
		return nil, err
	}

	// Only a top-level object can carry a signature member, and JCS output opens
	// one with '{'.
	if len(canonical) == 0 || canonical[0] != '{' {
		return canonical, nil
	}

	var object map[string]json.RawMessage
	if err := json.Unmarshal(canonical, &object); err != nil {
		return nil, fmt.Errorf("decode canonical object: %w", err)
	}

	if _, ok := object[signatureMember]; !ok {
		return canonical, nil
	}

	delete(object, signatureMember)

	stripped, err := json.Marshal(object)
	if err != nil {
		return nil, fmt.Errorf("marshal signing payload: %w", err)
	}

	return Canonicalize(stripped)
}

// CanonicalizeTrustManifest returns the canonical signing payload for a trust
// manifest. It only covers members represented by catalog.TrustManifest; verify
// against the manifest's original bytes with CanonicalizeForSignature when the
// producer may have included members this SDK does not model.
func CanonicalizeTrustManifest(manifest *catalog.TrustManifest) (string, error) {
	raw, err := json.Marshal(manifest)
	if err != nil {
		return "", fmt.Errorf("marshal trust manifest: %w", err)
	}

	canonical, err := CanonicalizeForSignature(raw)
	if err != nil {
		return "", err
	}

	return string(canonical), nil
}
