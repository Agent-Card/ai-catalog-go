// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-go)
// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package jws_test

import (
	"testing"

	"github.com/Agent-Card/ai-catalog-go/internal/jws"
)

func TestForbidden(t *testing.T) {
	tests := map[string]bool{
		"none":  true,
		"nOnE":  true,
		"ES256": false,
		"HS256": false,
	}

	for algorithm, want := range tests {
		if got := jws.Forbidden(algorithm); got != want {
			t.Errorf("Forbidden(%q) = %t, want %t", algorithm, got, want)
		}
	}
}

func TestParse(t *testing.T) {
	const (
		plain    = "eyJhbGciOiJFUzI1NiJ9..c2ln"
		withKey  = "eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDp3ZWI6YWNtZS5jb20ja2V5LTEiLCJ0eXAiOiJhaS1jYXRhbG9nK2p3cyJ9..c2ln"
		repeated = "eyJhbGciOiJFUzI1NiIsImFsZyI6IkVTMjU2In0..c2ln"
		numeric  = "eyJhbGciOjEyM30..c2ln"
		array    = "W10..c2ln"
	)

	header, err := jws.Parse(withKey)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	if header.Algorithm != "ES256" || header.KeyID != "did:web:acme.com#key-1" ||
		header.Type != "ai-catalog+jws" {
		t.Errorf("header = %+v", header)
	}

	if !header.Has("kid") || header.Has("jwk") {
		t.Error("Has should report exactly the members present")
	}

	for name, signature := range map[string]string{
		"repeated member": repeated, "non-string alg": numeric, "not an object": array, "no alg": "e30..c2ln",
	} {
		if _, err := jws.Parse(signature); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}

	if _, err := jws.Parse(plain); err != nil {
		t.Errorf("Parse(plain) error: %v", err)
	}
}

func TestDetached(t *testing.T) {
	tests := map[string]bool{
		"eyJhbGciOiJFUzI1NiJ9..c2ln":        true,
		"eyJhbGciOiJFUzI1NiJ9.cGF5.c2ln":    false,
		"eyJhbGciOiJFUzI1NiJ9.":             false,
		"eyJhbGciOiJFUzI1NiJ9..":            false,
		"..c2ln":                            false,
		"eyJhbGciOiJFUzI1NiJ9...c2ln.extra": false,
		"":                                  false,
	}

	for signature, want := range tests {
		if got := jws.Detached(signature); got != want {
			t.Errorf("Detached(%q) = %t, want %t", signature, got, want)
		}
	}
}
