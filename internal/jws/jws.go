// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-go)
// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

// Package jws holds the signature algorithm policy shared by the trust and
// validate packages, so both report the same verdict for the same signature.
package jws

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// Problem classifies what is wrong with a signature's declared algorithm.
type Problem int

const (
	// OK means the signature declares an algorithm that is not forbidden.
	OK Problem = iota

	// Malformed means the protected header does not declare an "alg".
	Malformed

	// Forbidden means the algorithm cannot establish third-party trust.
	Forbidden
)

// Result is the verdict on a signature's declared algorithm.
type Result struct {
	// Problem is OK when the signature needs no diagnostic.
	Problem Problem

	// Algorithm is the declared "alg"; it is empty when Problem is Malformed.
	Algorithm string

	// Message describes the problem; it is empty when Problem is OK.
	Message string
}

// Check inspects the "alg" in the protected header of a JWS compact
// serialization. "none" carries no proof and the HMAC family only proves
// possession of a shared secret, so neither can establish third-party trust.
func Check(signature string) Result {
	algorithm, ok := algorithmOf(signature)
	if !ok {
		return Result{
			Problem: Malformed,
			Message: "signature JWS header must be base64url-encoded JSON declaring an 'alg'",
		}
	}

	if forbidden(algorithm) {
		return Result{
			Problem:   Forbidden,
			Algorithm: algorithm,
			Message: fmt.Sprintf(
				"signature algorithm '%s' must be rejected; a signature requires an asymmetric algorithm",
				algorithm),
		}
	}

	return Result{Problem: OK, Algorithm: algorithm}
}

// forbidden reports whether algorithm is "none" or in the HMAC family. Matched
// case-insensitively.
func forbidden(algorithm string) bool {
	normalized := strings.ToUpper(algorithm)

	return normalized == "NONE" || strings.HasPrefix(normalized, "HS")
}

// algorithmOf returns the "alg" declared by a JWS compact serialization's
// protected header.
func algorithmOf(signature string) (string, bool) {
	encoded, _, _ := strings.Cut(signature, ".")

	header, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return "", false
	}

	var parsed struct {
		Algorithm string `json:"alg"`
	}

	if err := json.Unmarshal(header, &parsed); err != nil || parsed.Algorithm == "" {
		return "", false
	}

	return parsed.Algorithm, true
}
