// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-go)
// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

// Package jws reads JWS protected headers.
package jws

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// compactParts is the number of dot-separated segments in a compact JWS.
const compactParts = 3

// Header is a decoded JWS protected header.
type Header struct {
	// Algorithm is the "alg" member.
	Algorithm string

	// KeyID is the "kid" member, empty when absent.
	KeyID string

	// Type is the "typ" member, empty when absent.
	Type string

	members map[string]struct{}
}

// Has reports whether the header contains the named member.
func (h Header) Has(name string) bool {
	_, ok := h.members[name]

	return ok
}

// Parse decodes the protected header of a JWS compact serialization. It rejects
// a header that is not a JSON object, repeats a member name, has no "alg", or
// carries a non-string "alg", "kid" or "typ".
func Parse(signature string) (Header, error) {
	encoded, _, _ := strings.Cut(signature, ".")

	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return Header{}, fmt.Errorf("header is not base64url: %w", err)
	}

	fields, err := decodeMembers(raw)
	if err != nil {
		return Header{}, err
	}

	header := Header{members: make(map[string]struct{}, len(fields))}

	for name := range fields {
		header.members[name] = struct{}{}
	}

	if header.Algorithm, err = stringMember(fields, "alg"); err != nil || header.Algorithm == "" {
		return Header{}, errors.New("header declares no alg")
	}

	if header.KeyID, err = stringMember(fields, "kid"); err != nil {
		return Header{}, err
	}

	if header.Type, err = stringMember(fields, "typ"); err != nil {
		return Header{}, err
	}

	return header, nil
}

// decodeMembers decodes a JSON object into its raw members, rejecting repeated names.
func decodeMembers(raw []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))

	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return nil, errors.New("header is not a JSON object")
	}

	found := make(map[string]json.RawMessage)

	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, fmt.Errorf("header is not valid JSON: %w", err)
		}

		name, _ := token.(string)

		if _, dup := found[name]; dup {
			return nil, fmt.Errorf("header repeats the member %q", name)
		}

		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, fmt.Errorf("header is not valid JSON: %w", err)
		}

		found[name] = value
	}

	if _, err := decoder.Token(); err != nil {
		return nil, fmt.Errorf("header is not valid JSON: %w", err)
	}

	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("header has trailing content")
	}

	return found, nil
}

// stringMember returns the named member as a string; absent members read as "".
func stringMember(fields map[string]json.RawMessage, name string) (string, error) {
	raw, ok := fields[name]
	if !ok {
		return "", nil
	}

	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", fmt.Errorf("header member %q is not a string", name)
	}

	return value, nil
}

// Detached reports whether signature is a compact serialization with the
// payload omitted: a non-empty header and signature around an empty payload.
func Detached(signature string) bool {
	parts := strings.Split(signature, ".")

	return len(parts) == compactParts && parts[0] != "" && parts[1] == "" && parts[2] != ""
}

// Forbidden reports whether algorithm is "none", which proves nothing. Matched
// case-insensitively.
func Forbidden(algorithm string) bool {
	return strings.EqualFold(algorithm, "none")
}
