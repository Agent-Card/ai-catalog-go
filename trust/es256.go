// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-go)
// SPDX-License-Identifier: Apache-2.0

package trust

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"

	"github.com/Agent-Card/ai-catalog-go/internal/jws"
)

// Errors of ES256 verification, matchable with errors.Is.
var (
	// ErrInvalidKey indicates a JWK that is not a P-256 verification key.
	ErrInvalidKey = errors.New("invalid P-256 key")

	// ErrInvalidJWS indicates a JWS that is not a plain ES256 detached compact serialization.
	ErrInvalidJWS = errors.New("invalid ES256 JWS")

	// ErrSignatureMismatch indicates a well-formed signature that does not verify.
	ErrSignatureMismatch = errors.New("signature does not match")
)

const (
	algorithmES256 = "ES256"
	coordinateLen  = 32
	signatureLen   = 2 * coordinateLen
	sec1Uncompress = 0x04
	jwsParts       = 3
)

// ParseES256Key reads a P-256 public key from a JWK, rejecting private key
// material and members that forbid verifying ES256 signatures.
func ParseES256Key(jwk []byte) (*ecdsa.PublicKey, error) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(jwk, &members); err != nil || members == nil {
		return nil, fmt.Errorf("%w: the key is not a JSON object", ErrInvalidKey)
	}

	if text(members, "kty") != "EC" {
		return nil, fmt.Errorf(`%w: kty must be "EC"`, ErrInvalidKey)
	}

	if text(members, "crv") != "P-256" {
		return nil, fmt.Errorf(`%w: crv must be "P-256"`, ErrInvalidKey)
	}

	if err := checkKeyUse(members); err != nil {
		return nil, err
	}

	point := []byte{sec1Uncompress}

	for _, name := range []string{"x", "y"} {
		coordinate, err := base64.RawURLEncoding.DecodeString(text(members, name))
		if err != nil || len(coordinate) != coordinateLen {
			return nil, fmt.Errorf("%w: %s must be a 32-byte base64url value", ErrInvalidKey, name)
		}

		point = append(point, coordinate...)
	}

	key, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
	if err != nil {
		return nil, fmt.Errorf("%w: x and y are not a point on the curve", ErrInvalidKey)
	}

	return key, nil
}

func checkKeyUse(members map[string]json.RawMessage) error {
	if _, private := members["d"]; private {
		return fmt.Errorf("%w: the key contains private key material", ErrInvalidKey)
	}

	if _, ok := members["alg"]; ok && text(members, "alg") != algorithmES256 {
		return fmt.Errorf(`%w: alg must be "ES256"`, ErrInvalidKey)
	}

	if _, ok := members["use"]; ok && text(members, "use") != "sig" {
		return fmt.Errorf(`%w: use must be "sig"`, ErrInvalidKey)
	}

	if raw, ok := members["key_ops"]; ok {
		var operations []string
		if json.Unmarshal(raw, &operations) != nil || !slices.Contains(operations, "verify") {
			return fmt.Errorf(`%w: key_ops must permit "verify"`, ErrInvalidKey)
		}
	}

	return nil
}

// text returns a string member, or "" when it is absent or not a string.
func text(members map[string]json.RawMessage, name string) string {
	var value string
	if err := json.Unmarshal(members[name], &value); err != nil {
		return ""
	}

	return value
}

// VerifyES256 verifies an ES256 detached JWS over payload. Header members other
// than alg, b64 and crit are the caller's to check.
func VerifyES256(signature string, payload []byte, key *ecdsa.PublicKey) error {
	parts := strings.Split(signature, ".")
	if len(parts) != jwsParts || parts[1] != "" {
		return fmt.Errorf("%w: not a detached compact serialization", ErrInvalidJWS)
	}

	header, err := jws.Parse(signature)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidJWS, err)
	}

	if header.Algorithm != algorithmES256 {
		return fmt.Errorf(`%w: alg must be "ES256"`, ErrInvalidJWS)
	}

	for _, member := range []string{"b64", "crit"} {
		if header.Has(member) {
			return fmt.Errorf("%w: the header must not contain %q", ErrInvalidJWS, member)
		}
	}

	raw, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(raw) != signatureLen {
		return fmt.Errorf("%w: the signature is not a 64-byte base64url value", ErrInvalidJWS)
	}

	der, err := asn1.Marshal(struct{ R, S *big.Int }{
		R: new(big.Int).SetBytes(raw[:coordinateLen]),
		S: new(big.Int).SetBytes(raw[coordinateLen:]),
	})
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidJWS, err)
	}

	input := parts[0] + "." + base64.RawURLEncoding.EncodeToString(payload)
	sum := sha256.Sum256([]byte(input))

	if !ecdsa.VerifyASN1(key, sum[:], der) {
		return ErrSignatureMismatch
	}

	return nil
}
