// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-go)
// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package trust_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/Agent-Card/ai-catalog-go/catalog"
	"github.com/Agent-Card/ai-catalog-go/internal/fixture"
	"github.com/Agent-Card/ai-catalog-go/trust"
)

// SHA-256, SHA-384 and SHA-512 of the ASCII bytes "test".
const (
	testSHA256 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	testSHA384 = "768412320f7b0aa5812fce428dc4706b3cae50e02a64caa16a782249bfe8efc4b7ef1ccb126255d196047dfedf17a0a9"
	testSHA512 = "ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff"
)

func manifestShapes(t *testing.T) map[string]json.RawMessage {
	t.Helper()

	var shapes map[string]json.RawMessage
	if err := json.Unmarshal(fixture.Read(t, "manifest_shapes.json"), &shapes); err != nil {
		t.Fatalf("decode manifest shapes: %v", err)
	}

	return shapes
}

func TestVerifyDigest(t *testing.T) {
	for _, digest := range []string{"sha256:" + testSHA256, "sha384:" + testSHA384, "sha512:" + testSHA512} {
		if ok, err := trust.VerifyDigest(digest, []byte("test")); err != nil || !ok {
			t.Errorf("VerifyDigest(%.14s) = %t, %v, want a match", digest, ok, err)
		}

		if ok, err := trust.VerifyDigest(digest, []byte("tampered")); err != nil || ok {
			t.Errorf("VerifyDigest(%.14s, tampered) = %t, %v, want no match", digest, ok, err)
		}
	}
}

func TestParseDigest_Rejects(t *testing.T) {
	tests := []struct {
		value string
		want  error
	}{
		{"md5:abcd", trust.ErrWeakDigestAlgorithm},
		{"sha1:abcd", trust.ErrWeakDigestAlgorithm},
		{"crc32:abcd", trust.ErrUnsupportedDigestAlgorithm},
		{"sha256:not-hex!", trust.ErrInvalidDigestHex},
		{"sha256:abc", trust.ErrInvalidDigestHex},
		{"sha256:" + testSHA256 + "ab", trust.ErrInvalidDigestHex},
		{"missing-colon", trust.ErrInvalidDigestFormat},
		{"sha256:", trust.ErrInvalidDigestFormat},
	}

	for _, tc := range tests {
		if _, err := trust.ParseDigest(tc.value); !errors.Is(err, tc.want) {
			t.Errorf("ParseDigest(%q) error = %v, want %v", tc.value, err, tc.want)
		}
	}
}

// A manifest read from a document canonicalizes to what a verifier computes
// from the published bytes, whatever shape they have. Re-serializing the struct
// would drop several of these shapes and sign a different document.
func TestCanonicalizeTrustManifest_MatchesPublishedBytes(t *testing.T) {
	for name, published := range manifestShapes(t) {
		t.Run(name, func(t *testing.T) {
			want, err := trust.CanonicalizeForSignature(published)
			if err != nil {
				t.Fatalf("CanonicalizeForSignature error: %v", err)
			}

			var manifest catalog.TrustManifest
			if err := json.Unmarshal(published, &manifest); err != nil {
				t.Fatalf("decode manifest: %v", err)
			}

			got, err := trust.CanonicalizeTrustManifest(&manifest)
			if err != nil {
				t.Fatalf("CanonicalizeTrustManifest error: %v", err)
			}

			if got != string(want) {
				t.Errorf("canonical form differs from the published bytes\n got: %s\nwant: %s", got, want)
			}
		})
	}
}

// Once a decoded manifest is changed, the bytes it came from no longer describe
// it, so the payload must follow the change.
func TestCanonicalizeTrustManifest_FollowsChangesAfterDecoding(t *testing.T) {
	var manifest catalog.TrustManifest
	if err := json.Unmarshal(manifestShapes(t)["unknown member"], &manifest); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}

	manifest.Identity = "urn:example:b"

	got, err := trust.CanonicalizeTrustManifest(&manifest)
	if err != nil {
		t.Fatalf("CanonicalizeTrustManifest error: %v", err)
	}

	if want := `{"identity":"urn:example:b"}`; got != want {
		t.Errorf("canonical form = %s, want %s", got, want)
	}
}

// The detached signature never covers itself, and members the SDK does not
// model stay in the payload.
func TestCanonicalizeForSignature(t *testing.T) {
	got, err := trust.CanonicalizeForSignature(manifestShapes(t)["signed with unmodelled member"])
	if err != nil {
		t.Fatalf("CanonicalizeForSignature error: %v", err)
	}

	if want := `{"futureMember":42,"identity":"urn:example"}`; string(got) != want {
		t.Errorf("CanonicalizeForSignature = %s, want %s", got, want)
	}
}

// Canonicalization itself is the cyberphone library; this checks that it is
// wired up for RFC 8785 and that input that is not I-JSON is rejected.
func TestCanonicalize(t *testing.T) {
	got, err := trust.Canonicalize(fixture.Read(t, "rfc8785_input.json"))
	if err != nil {
		t.Fatalf("Canonicalize error: %v", err)
	}

	// RFC 8785 Appendix B.
	want := `{"literals":[null,true,false],` +
		`"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],` +
		"\"string\":\"\u20ac$\\u000f\\nA'B\\\"\\\\\\\\\\\"/\"}"

	if string(got) != want {
		t.Errorf("Canonicalize =\n  %s\nwant\n  %s", got, want)
	}

	rejected := map[string]string{
		"trailing content":       `{"a":1} trailing`,
		"malformed number":       `{"n":01}`,
		"duplicate member names": `{"a":1,"a":2}`,
		"lone surrogate":         `{"a":"\ud800"}`,
		"invalid UTF-8":          "{\"a\":\"\xff\"}",
	}

	for name, input := range rejected {
		if _, err := trust.Canonicalize([]byte(input)); !errors.Is(err, trust.ErrUncanonicalizableJSON) {
			t.Errorf("%s: got error %v, want ErrUncanonicalizableJSON", name, err)
		}
	}
}
