// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-go)
// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package catalog

import "testing"

func TestPublisherDomain(t *testing.T) {
	cases := []struct {
		identifier string
		want       string
		wantOK     bool
	}{
		{"urn:air:Acme.com:agent:finance", "acme.com", true},
		{"URN:AIR:acme.com:agent:finance", "acme.com", true},
		{"urn:example:agent", "", false},
		{"urn:air:", "", false},
	}

	for _, tc := range cases {
		got, ok := PublisherDomain(tc.identifier)
		if got != tc.want || ok != tc.wantOK {
			t.Errorf("PublisherDomain(%q) = (%q, %t), want (%q, %t)",
				tc.identifier, got, ok, tc.want, tc.wantOK)
		}
	}
}

func TestIdentityDomain(t *testing.T) {
	cases := []struct {
		identity string
		want     string
		wantOK   bool
	}{
		{"did:web:acme.com", "acme.com", true},
		{"did:web:acme.com%3A8443:user", "acme.com", true},
		{"urn:air:acme.com:agent:finance", "acme.com", true},
		{"spiffe://acme.com/workload", "acme.com", true},
		{"https://user@acme.com:8443/path", "acme.com", true},
		{"plain-identifier", "", false},
		{"urn:acme:agent:finance", "", false},
	}

	for _, tc := range cases {
		got, ok := IdentityDomain(tc.identity)
		if got != tc.want || ok != tc.wantOK {
			t.Errorf("IdentityDomain(%q) = (%q, %t), want (%q, %t)",
				tc.identity, got, ok, tc.want, tc.wantOK)
		}
	}
}

func TestIdentityBindsToEntry(t *testing.T) {
	cases := []struct {
		name        string
		identifier  string
		identity    string
		wantAligned bool
		wantApplies bool
	}{
		{
			name:        "aligned by domain without exact equality",
			identifier:  "urn:air:acme.com:agent:finance",
			identity:    "did:web:acme.com",
			wantAligned: true,
			wantApplies: true,
		},
		{
			name:        "different domain",
			identifier:  "urn:air:acme.com:agent:finance",
			identity:    "did:web:evil.example",
			wantAligned: false,
			wantApplies: true,
		},
		{
			// An identity with no trust domain cannot align, so the binding
			// check must fail rather than be skipped.
			name:        "identity without a trust domain",
			identifier:  "urn:air:acme.com:agent:finance",
			identity:    "urn:acme:agent:finance",
			wantAligned: false,
			wantApplies: true,
		},
		{
			name:        "non-URI identity",
			identifier:  "urn:air:acme.com:agent:finance",
			identity:    "plain-identifier",
			wantAligned: false,
			wantApplies: true,
		},
		{
			// Without a urn:air identifier there is no publisher domain to bind
			// against, so the rule does not apply.
			name:        "entry without a publisher domain",
			identifier:  "urn:example:agent",
			identity:    "did:web:acme.com",
			wantAligned: true,
			wantApplies: false,
		},
		{
			name:        "neither side carries a domain",
			identifier:  "urn:example:agent",
			identity:    "anything",
			wantAligned: true,
			wantApplies: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			aligned, applies := IdentityBindsToEntry(tc.identifier, tc.identity)
			if aligned != tc.wantAligned || applies != tc.wantApplies {
				t.Errorf("IdentityBindsToEntry(%q, %q) = (%t, %t), want (%t, %t)",
					tc.identifier, tc.identity, aligned, applies,
					tc.wantAligned, tc.wantApplies)
			}
		})
	}
}
