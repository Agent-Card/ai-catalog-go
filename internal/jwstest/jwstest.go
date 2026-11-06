// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-go)
// SPDX-License-Identifier: Apache-2.0

// Package jwstest signs detached ES256 JWS values for tests.
package jwstest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"
)

const (
	coordinateLen = 32
	signatureLen  = 2 * coordinateLen
)

// Key is a P-256 signing key.
type Key struct {
	private *ecdsa.PrivateKey
}

// NewKey generates a key.
func NewKey(tb testing.TB) *Key {
	tb.Helper()

	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("generate key: %v", err)
	}

	return &Key{private}
}

// JWK returns the public key as a JWK object.
func (k *Key) JWK(tb testing.TB) map[string]any {
	tb.Helper()

	point, err := k.private.PublicKey.Bytes()
	if err != nil {
		tb.Fatalf("encode key: %v", err)
	}

	return map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(point[1 : 1+coordinateLen]),
		"y":   base64.RawURLEncoding.EncodeToString(point[1+coordinateLen:]),
	}
}

// Sign returns a detached compact JWS over payload with the given protected header.
func (k *Key) Sign(tb testing.TB, header map[string]any, payload []byte) string {
	tb.Helper()

	encoded, err := json.Marshal(header)
	if err != nil {
		tb.Fatalf("encode header: %v", err)
	}

	protected := base64.RawURLEncoding.EncodeToString(encoded)
	sum := sha256.Sum256([]byte(protected + "." + base64.RawURLEncoding.EncodeToString(payload)))

	der, err := ecdsa.SignASN1(rand.Reader, k.private, sum[:])
	if err != nil {
		tb.Fatalf("sign: %v", err)
	}

	var parts struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(der, &parts); err != nil {
		tb.Fatalf("decode signature: %v", err)
	}

	raw := make([]byte, signatureLen)
	parts.R.FillBytes(raw[:coordinateLen])
	parts.S.FillBytes(raw[coordinateLen:])

	return protected + ".." + base64.RawURLEncoding.EncodeToString(raw)
}
