// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-go)
// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

// Package identity implements the identifier rules of the AI Catalog
// did:web Publisher Profile.
package identity

import (
	"net/netip"
	"regexp"
	"strings"
)

const (
	urnAIRPrefix = "urn:air:"
	didWebPrefix = "did:web:"
)

// domain matches a lowercase ASCII DNS name; an IDN is accepted in A-label form.
var domain = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`)

// Publisher returns the {publisher} component of a
// urn:air:{publisher}:{namespace}:{name} identifier.
func Publisher(identifier string) (string, bool) {
	rest, ok := strings.CutPrefix(identifier, urnAIRPrefix)
	if !ok {
		return "", false
	}

	publisher, _, _ := strings.Cut(rest, ":")

	return publisher, publisher != ""
}

// ValidPublisher reports whether publisher can be the domain of a root did:web
// DID: lowercase ASCII, with no port, IP address or trailing root dot.
func ValidPublisher(publisher string) bool {
	if !domain.MatchString(publisher) {
		return false
	}

	_, err := netip.ParseAddr(publisher)

	return err != nil
}

// DID returns the did:web identity an issuer must use for publisher.
func DID(publisher string) string {
	return didWebPrefix + publisher
}
