// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-go)
// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package identity_test

import (
	"strings"
	"testing"

	"github.com/Agent-Card/ai-catalog-go/internal/identity"
)

const acme = "acme.com"

func TestPublisher(t *testing.T) {
	tests := []struct {
		identifier string
		want       string
		ok         bool
	}{
		{"urn:air:acme.com:agent:finance", acme, true},
		{"urn:air:acme.com", acme, true},
		{"urn:air::agent:finance", "", false},
		{"URN:AIR:acme.com:agent:finance", "", false},
		{"urn:example:agent", "", false},
	}

	for _, tc := range tests {
		got, ok := identity.Publisher(tc.identifier)
		if got != tc.want || ok != tc.ok {
			t.Errorf("Publisher(%q) = (%q, %t), want (%q, %t)", tc.identifier, got, ok, tc.want, tc.ok)
		}
	}
}

func TestValidPublisher(t *testing.T) {
	tests := map[string]bool{
		acme:                             true,
		"xn--bcher-kva.com":              true,
		"localhost":                      true,
		"Acme.com":                       false,
		"acme.com:8443":                  false,
		"acme.com.":                      false,
		"192.168.0.1":                    false,
		"[::1]":                          false,
		"bücher.com":                     false,
		"-acme.com":                      false,
		strings.Repeat("a", 63) + ".com": true,
		strings.Repeat("a", 64) + ".com": false,
		strings.Repeat("a.", 126) + "a":  true,
		strings.Repeat("a.", 127) + "a":  false,
		"":                               false,
	}

	for publisher, want := range tests {
		if got := identity.ValidPublisher(publisher); got != want {
			t.Errorf("ValidPublisher(%q) = %t, want %t", publisher, got, want)
		}
	}
}

func TestDID(t *testing.T) {
	if got := identity.DID(acme); got != "did:web:"+acme {
		t.Errorf("DID = %q", got)
	}
}
