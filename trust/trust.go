// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-go)
// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

// Package trust provides digest verification and JCS (RFC 8785) canonicalization.
// Rule checking lives in package validate.
package trust

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Digest errors, matchable with errors.Is.
var (
	// ErrInvalidDigestFormat indicates a digest that is not "algorithm:hex".
	ErrInvalidDigestFormat = errors.New("digest must use the format 'algorithm:hex-value'")

	// ErrUnsupportedDigestAlgorithm indicates an unrecognized digest algorithm.
	ErrUnsupportedDigestAlgorithm = errors.New("unsupported digest algorithm")

	// ErrWeakDigestAlgorithm indicates a digest algorithm weaker than SHA-256.
	ErrWeakDigestAlgorithm = errors.New("digest algorithm is weaker than SHA-256")

	// ErrInvalidDigestHex indicates a value that is not lowercase hex of the required length.
	ErrInvalidDigestHex = errors.New("invalid digest hex value")
)

// ParsedDigest is a validated "algorithm:hex" digest.
type ParsedDigest struct {
	algorithm string
	hexValue  string
}

// Algorithm returns the lowercased algorithm.
func (d *ParsedDigest) Algorithm() string { return d.algorithm }

// HexValue returns the lowercased hex value.
func (d *ParsedDigest) HexValue() string { return d.hexValue }

// Hex lengths of the accepted algorithms.
const (
	sha256HexLen = 64
	sha384HexLen = 96
	sha512HexLen = 128
)

// ParseDigest parses an "algorithm:hex" digest. Only SHA-256, SHA-384 and
// SHA-512 are accepted.
func ParseDigest(value string) (*ParsedDigest, error) {
	algorithm, hexValue, found := strings.Cut(value, ":")
	if !found || algorithm == "" || hexValue == "" || strings.Count(value, ":") != 1 {
		return nil, fmt.Errorf("%w, found %q", ErrInvalidDigestFormat, value)
	}

	normalized := strings.ToLower(algorithm)

	var expectedLen int

	switch normalized {
	case "sha256":
		expectedLen = sha256HexLen
	case "sha384":
		expectedLen = sha384HexLen
	case "sha512":
		expectedLen = sha512HexLen
	case "md5", "sha1", "sha224":
		return nil, fmt.Errorf("%w: %q", ErrWeakDigestAlgorithm, normalized)
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedDigestAlgorithm, normalized)
	}

	if len(hexValue) != expectedLen {
		return nil, fmt.Errorf("%w: %s requires %d hex characters, found %d",
			ErrInvalidDigestHex, normalized, expectedLen, len(hexValue))
	}

	if _, err := hex.DecodeString(hexValue); err != nil {
		return nil, fmt.Errorf("%w: %q contains non-hex characters",
			ErrInvalidDigestHex, hexValue)
	}

	return &ParsedDigest{algorithm: normalized, hexValue: strings.ToLower(hexValue)}, nil
}

// VerifyBytes reports whether the digest matches the SHA sum of data.
func (d *ParsedDigest) VerifyBytes(data []byte) bool {
	var sum []byte

	switch d.algorithm {
	case "sha256":
		digest := sha256.Sum256(data)
		sum = digest[:]
	case "sha384":
		digest := sha512.Sum384(data)
		sum = digest[:]
	case "sha512":
		digest := sha512.Sum512(data)
		sum = digest[:]
	default:
		return false
	}

	return hex.EncodeToString(sum) == d.hexValue
}

// VerifyDigest parses expectedDigest and reports whether it matches data. It
// returns an error only when expectedDigest is malformed.
func VerifyDigest(expectedDigest string, data []byte) (bool, error) {
	parsed, err := ParseDigest(expectedDigest)
	if err != nil {
		return false, err
	}

	return parsed.VerifyBytes(data), nil
}
