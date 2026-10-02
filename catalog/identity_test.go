// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-go)
// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package catalog

import "testing"

const (
	acmeDomain  = "acme.com"
	acmeAgentID = "urn:air:acme.com:agent:finance"
	acmeDIDWeb  = "did:web:acme.com"

	domainlessID = "urn:example:agent"
)

func TestPublisherDomain(t *testing.T) {
	cases := []struct {
		identifier string
		want       string
		wantOK     bool
	}{
		{"urn:air:Acme.com:agent:finance", acmeDomain, true},
		{"URN:AIR:acme.com:agent:finance", acmeDomain, true},
		{domainlessID, "", false},
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
		{acmeDIDWeb, acmeDomain, true},
		{"did:web:acme.com%3A8443:user", acmeDomain, true},
		{acmeAgentID, acmeDomain, true},
		{"spiffe://acme.com/workload", acmeDomain, true},
		{"https://user@acme.com:8443/path", acmeDomain, true},
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
			identifier:  acmeAgentID,
			identity:    acmeDIDWeb,
			wantAligned: true,
			wantApplies: true,
		},
		{
			name:        "different domain",
			identifier:  acmeAgentID,
			identity:    "did:web:evil.example",
			wantAligned: false,
			wantApplies: true,
		},
		{
			// An identity with no trust domain cannot align, so the binding
			// check must fail rather than be skipped.
			name:        "identity without a trust domain",
			identifier:  acmeAgentID,
			identity:    "urn:acme:agent:finance",
			wantAligned: false,
			wantApplies: true,
		},
		{
			name:        "non-URI identity",
			identifier:  acmeAgentID,
			identity:    "plain-identifier",
			wantAligned: false,
			wantApplies: true,
		},
		{
			// Without a urn:air identifier there is no publisher domain to bind
			// against, so the rule does not apply.
			name:        "entry without a publisher domain",
			identifier:  domainlessID,
			identity:    acmeDIDWeb,
			wantAligned: true,
			wantApplies: false,
		},
		{
			name:        "neither side carries a domain",
			identifier:  domainlessID,
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
