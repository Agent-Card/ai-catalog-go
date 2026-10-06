// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-go)
// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package jws_test

import (
	"strings"
	"testing"

	"github.com/Agent-Card/ai-catalog-go/internal/jws"
)

func TestCheck(t *testing.T) {
	const malformed = "declaring an 'alg'"

	tests := []struct {
		name      string
		signature string
		want      jws.Problem
		algorithm string
		contains  string
	}{
		{"ES256 is accepted", "eyJhbGciOiJFUzI1NiJ9..c2ln", jws.OK, "ES256", ""},
		{
			"an algorithm outside the allowlist is not this package's concern",
			"eyJhbGciOiJFUzUxMiJ9..c2ln", jws.OK, "ES512", "",
		},
		{"alg none is forbidden", "eyJhbGciOiJub25lIn0..c2ln", jws.Forbidden, "none", "'none' must be rejected"},
		{
			"alg none is matched case-insensitively",
			"eyJhbGciOiJuT25FIn0..c2ln", jws.Forbidden, "nOnE", "'nOnE' must be rejected",
		},
		{"HS256 is forbidden", "eyJhbGciOiJIUzI1NiJ9..c2ln", jws.Forbidden, "HS256", "'HS256' must be rejected"},
		{"header is not base64url", "!!!..c2ln", jws.Malformed, "", malformed},
		{"header is not JSON", "bm90LWpzb24..c2ln", jws.Malformed, "", malformed},
		{"header has no alg", "e30..c2ln", jws.Malformed, "", malformed},
		{"empty signature", "", jws.Malformed, "", malformed},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := jws.Check(tc.signature)

			if got.Problem != tc.want {
				t.Fatalf("Problem = %v, want %v (message %q)", got.Problem, tc.want, got.Message)
			}

			if got.Algorithm != tc.algorithm {
				t.Errorf("Algorithm = %q, want %q", got.Algorithm, tc.algorithm)
			}

			if !strings.Contains(got.Message, tc.contains) {
				t.Errorf("Message = %q, want it to contain %q", got.Message, tc.contains)
			}

			if tc.want == jws.OK && got.Message != "" {
				t.Errorf("Message = %q, want empty for OK", got.Message)
			}
		})
	}
}

func TestCheck_MessageIsNotSpecificToTrustManifests(t *testing.T) {
	got := jws.Check("eyJhbGciOiJub25lIn0..c2ln")

	if strings.Contains(got.Message, "trust manifest") {
		t.Errorf("the verdict is shared with catalog signatures, got %q", got.Message)
	}
}
