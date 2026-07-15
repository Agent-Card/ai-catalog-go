// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package catalog

import "strings"

const urnAIRPrefix = "urn:air:"

const didWebPrefix = "did:web:"

// PublisherDomain returns the lowercased publisher domain segment of a
// urn:air:{publisher}:{namespace}:{name} identifier. The second result is false
// for non-urn:air identifiers, for which the spec does not define a publisher
// domain.
func PublisherDomain(identifier string) (string, bool) {
	if !strings.HasPrefix(strings.ToLower(identifier), urnAIRPrefix) {
		return "", false
	}

	publisher, _, _ := strings.Cut(identifier[len(urnAIRPrefix):], ":")
	if publisher == "" {
		return "", false
	}

	return strings.ToLower(publisher), true
}

// IdentityDomain returns the lowercased authority or trust domain of a Trust
// Manifest identity URI, handling urn:air, did:web, and authority-based schemes
// (spiffe://, https://, ...). The second result is false when no domain can be
// determined.
func IdentityDomain(identity string) (string, bool) {
	id := strings.TrimSpace(identity)
	lower := strings.ToLower(id)

	switch {
	case strings.HasPrefix(lower, urnAIRPrefix):
		return PublisherDomain(id)
	case strings.HasPrefix(lower, didWebPrefix):
		return didWebDomain(id)
	default:
		return authorityDomain(id)
	}
}

// IdentityBindsToEntry reports whether a Trust Manifest identity's domain aligns
// with the publisher domain of an entry identifier, per the spec's identity
// binding. It returns (aligned, determinable); when determinable is false the
// binding cannot be evaluated and aligned is reported as true.
func IdentityBindsToEntry(identifier, identity string) (bool, bool) {
	publisher, pubOK := PublisherDomain(identifier)
	domain, idOK := IdentityDomain(identity)

	if !pubOK || !idOK {
		return true, false
	}

	return publisher == domain, true
}

// didWebDomain returns the domain of a did:web identifier: the first
// colon-separated segment after the method name, with any percent-encoded port
// (%3A) stripped.
func didWebDomain(id string) (string, bool) {
	segment, _, _ := strings.Cut(id[len(didWebPrefix):], ":")

	if i := strings.Index(strings.ToLower(segment), "%3a"); i >= 0 {
		segment = segment[:i]
	}

	if segment == "" {
		return "", false
	}

	return strings.ToLower(segment), true
}

// authorityDomain extracts the host from a URI with an authority component
// (scheme://authority/path), stripping any userinfo and port.
func authorityDomain(id string) (string, bool) {
	_, authority, found := strings.Cut(id, "://")
	if !found {
		return "", false
	}

	if host, _, ok := strings.Cut(authority, "/"); ok {
		authority = host
	}

	if at := strings.LastIndexByte(authority, '@'); at >= 0 {
		authority = authority[at+1:]
	}

	if c := strings.LastIndexByte(authority, ':'); c >= 0 {
		authority = authority[:c]
	}

	if authority == "" {
		return "", false
	}

	return strings.ToLower(authority), true
}
