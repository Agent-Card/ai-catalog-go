// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-go)
// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package trust

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"unicode/utf8"

	"github.com/Agent-Card/ai-catalog-go/catalog"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

// ErrUncanonicalizableJSON indicates input that cannot be canonicalized, such as
// an out-of-range number, a duplicate member name or trailing content.
var ErrUncanonicalizableJSON = errors.New("JSON cannot be canonicalized")

// signatureMember is excluded from the signing payload; a signature cannot cover itself.
const signatureMember = "signature"

// Canonicalize returns the JCS (RFC 8785) form of a JSON object or array. Input
// that is not I-JSON (RFC 7493) is rejected: duplicate member names, lone
// surrogates and invalid UTF-8 canonicalize ambiguously.
func Canonicalize(data []byte) ([]byte, error) {
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("%w: input is not valid UTF-8", ErrUncanonicalizableJSON)
	}

	// The canonicalizer accepts some invalid number literals, such as "01".
	if !json.Valid(data) {
		return nil, fmt.Errorf("%w: input is not well-formed JSON", ErrUncanonicalizableJSON)
	}

	canonical, err := jsoncanonicalizer.Transform(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUncanonicalizableJSON, err)
	}

	return canonical, nil
}

// CanonicalizeForSignature returns the JCS form of a JSON document without its
// top-level "signature" member, the payload a detached JWS covers. It works on
// the original bytes, so members the SDK does not model are included.
func CanonicalizeForSignature(data []byte) ([]byte, error) {
	// Canonicalize first: it rejects duplicate members, which the round-trip below would collapse.
	canonical, err := Canonicalize(data)
	if err != nil {
		return nil, err
	}

	// Only an object can carry a signature member; JCS output opens one with '{'.
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

// CanonicalizeTrustManifest returns the signing payload for a trust manifest,
// without its "signature" member.
//
// A decoded manifest is canonicalized from its original bytes, so everything the
// producer signed is covered. A manifest built in code or changed after decoding
// is canonicalized from its serialization, which omits nil slices and maps and
// empty strings; producers should sign what this returns.
func CanonicalizeTrustManifest(manifest *catalog.TrustManifest) (string, error) {
	raw := decodedBytes(manifest)

	if raw == nil {
		var err error

		raw, err = json.Marshal(manifest)
		if err != nil {
			return "", fmt.Errorf("marshal trust manifest: %w", err)
		}
	}

	canonical, err := CanonicalizeForSignature(raw)
	if err != nil {
		return "", err
	}

	return string(canonical), nil
}

// decodedBytes returns the bytes manifest was decoded from, or nil if absent or stale.
func decodedBytes(manifest *catalog.TrustManifest) []byte {
	raw := manifest.Raw()
	if raw == nil {
		return nil
	}

	var decoded catalog.TrustManifest
	if err := json.Unmarshal(raw, &decoded); err != nil || !reflect.DeepEqual(&decoded, manifest) {
		return nil
	}

	return raw
}
