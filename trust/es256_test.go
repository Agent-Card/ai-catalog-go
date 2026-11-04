// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-go)
// SPDX-License-Identifier: Apache-2.0

package trust_test

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"testing"

	"github.com/Agent-Card/ai-catalog-go/internal/jwstest"
	"github.com/Agent-Card/ai-catalog-go/trust"
)

// RFC 7515, Appendix A.3.
const (
	es256 = "ES256"
	alg   = "alg"
)

const (
	rfcKey       = `{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}`
	rfcHeader    = "eyJhbGciOiJFUzI1NiJ9"
	rfcPayload   = "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
	rfcSignature = "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
)

func jwkBytes(t *testing.T, jwk map[string]any) []byte {
	t.Helper()

	encoded, err := json.Marshal(jwk)
	if err != nil {
		t.Fatalf("encode jwk: %v", err)
	}

	return encoded
}

type testKey struct {
	signer *jwstest.Key
	public *ecdsa.PublicKey
}

func jwkTestKey(t *testing.T) *testKey {
	t.Helper()

	signer := jwstest.NewKey(t)

	public, err := trust.ParseES256Key(jwkBytes(t, signer.JWK(t)))
	if err != nil {
		t.Fatalf("parse generated key: %v", err)
	}

	return &testKey{signer, public}
}

func (k *testKey) sign(t *testing.T, header map[string]any, payload []byte) string {
	t.Helper()

	return k.signer.Sign(t, header, payload)
}

func TestVerifyES256_RFC7515Example(t *testing.T) {
	key, err := trust.ParseES256Key([]byte(rfcKey))
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}

	payload, err := base64.RawURLEncoding.DecodeString(rfcPayload)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}

	if err := trust.VerifyES256(rfcHeader+".."+rfcSignature, payload, key); err != nil {
		t.Errorf("verify: %v", err)
	}
}

func TestVerifyES256_RejectsChangedPayloadAndOtherKey(t *testing.T) {
	signer, other := jwkTestKey(t), jwkTestKey(t)
	signature := signer.sign(t, map[string]any{alg: es256}, []byte("payload"))

	if err := trust.VerifyES256(signature, []byte("payload"), signer.public); err != nil {
		t.Fatalf("verify: %v", err)
	}

	for name, key := range map[string]*testKey{"changed payload": signer, "another key": other} {
		payload := []byte("payload")
		if name == "changed payload" {
			payload = []byte("changed")
		}

		if err := trust.VerifyES256(signature, payload, key.public); !errors.Is(err, trust.ErrSignatureMismatch) {
			t.Errorf("%s: err = %v, want ErrSignatureMismatch", name, err)
		}
	}
}

func TestVerifyES256_RejectsHeadersThatAreNotPlainES256(t *testing.T) {
	key := jwkTestKey(t)

	for name, header := range map[string]map[string]any{
		"none":   {alg: "none"},
		"hs256":  {alg: "HS256"},
		"no alg": {"typ": "x"},
		"b64":    {alg: es256, "b64": false},
		"crit":   {alg: es256, "crit": []string{"exp"}},
	} {
		signature := key.sign(t, header, []byte("payload"))

		if err := trust.VerifyES256(signature, []byte("payload"), key.public); !errors.Is(err, trust.ErrInvalidJWS) {
			t.Errorf("%s: err = %v, want ErrInvalidJWS", name, err)
		}
	}
}

func TestParseES256Key_RejectsKeysThatAreNotP256VerificationKeys(t *testing.T) {
	valid := map[string]any{}
	if err := json.Unmarshal([]byte(rfcKey), &valid); err != nil {
		t.Fatal(err)
	}

	for name, value := range map[string]any{
		"kty":     "RSA",
		"crv":     "P-384",
		"d":       "AA",
		alg:       "ES384",
		"use":     "enc",
		"key_ops": []string{"sign"},
		"x":       "AA",
	} {
		jwk := maps.Clone(valid)
		jwk[name] = value

		if _, err := trust.ParseES256Key(jwkBytes(t, jwk)); !errors.Is(err, trust.ErrInvalidKey) {
			t.Errorf("%s: err = %v, want ErrInvalidKey", name, err)
		}
	}

	offCurve := maps.Clone(valid)
	offCurve["y"] = valid["x"]

	if _, err := trust.ParseES256Key(jwkBytes(t, offCurve)); err == nil {
		t.Error("a point off the curve was accepted")
	}

	allowed := maps.Clone(valid)
	allowed["key_ops"], allowed["alg"], allowed["use"] = []string{"verify"}, es256, "sig"

	if _, err := trust.ParseES256Key(jwkBytes(t, allowed)); err != nil {
		t.Errorf("a permitted key was rejected: %v", err)
	}
}
