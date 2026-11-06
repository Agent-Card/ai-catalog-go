// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-go)
// SPDX-License-Identifier: Apache-2.0

package validate_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"testing"
	"time"

	"github.com/Agent-Card/ai-catalog-go/internal/jwstest"
	"github.com/Agent-Card/ai-catalog-go/trust"
	"github.com/Agent-Card/ai-catalog-go/validate"
)

const (
	identifierKey = "identifier"
	artifactID    = "urn:air:acme.com:agent:billing"
	artifactType  = "application/a2a-agent-card+json"
	artifactURL   = "https://acme.com/billing.json"
	didURL        = "https://acme.com/.well-known/did.json"
	now           = "2026-10-01T00:00:00Z"
)

var artifact = []byte(`{"name":"billing"}`)

type object = map[string]any

func digest(content []byte) string {
	return fmt.Sprintf("sha256:%x", sha256.Sum256(content))
}

func clock(t *testing.T, value string) validate.Option {
	t.Helper()

	at, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatalf("parse clock: %v", err)
	}

	return validate.WithClock(func() time.Time { return at })
}

// party is a did:web signer with its own key.
type party struct {
	did string
	key *jwstest.Key
}

func newParty(t *testing.T, domain string) party {
	t.Helper()

	return party{did: "did:web:" + domain, key: jwstest.NewKey(t)}
}

func (p party) kid() string { return p.did + "#key-1" }

func (p party) didDocument(t *testing.T) []byte {
	t.Helper()

	return marshal(t, object{
		"id": p.did,
		"verificationMethod": []object{{
			"id":           p.kid(),
			"controller":   p.did,
			"publicKeyJwk": p.key.JWK(t),
		}},
		"assertionMethod": []string{p.kid()},
	})
}

func marshal(t *testing.T, value any) []byte {
	t.Helper()

	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	return encoded
}

// sign attaches a signature to the object; typ is the JWS typ of its kind.
func (p party) sign(t *testing.T, subject object, typ string) object {
	t.Helper()

	signed := maps.Clone(subject)
	signature := object{
		"signer":    p.did,
		"profile":   "did-web-v1",
		"issuedAt":  "2026-09-12T10:00:00Z",
		"expiresAt": "2026-12-01T00:00:00Z",
	}
	signed["signature"] = signature

	payload, err := trust.CanonicalizeForSignature(marshal(t, signed))
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}

	signature["jws"] = p.key.Sign(t, object{"alg": "ES256", "kid": p.kid(), "typ": typ}, payload)

	return signed
}

func (p party) endorse(t *testing.T) object {
	t.Helper()

	return p.sign(t, object{
		"contributor": p.did,
		"subject":     object{identifierKey: artifactID, "type": artifactType, "digest": digest(artifact)},
	}, "ai-catalog-trust-manifest+jws")
}

type site map[string][]byte

func newSite(t *testing.T, parties ...party) site {
	t.Helper()

	s := site{artifactURL: artifact}

	for _, p := range parties {
		s["https://"+p.did[len("did:web:"):]+"/.well-known/did.json"] = p.didDocument(t)
	}

	return s
}

func (s site) Fetch(_ context.Context, url string) ([]byte, error) {
	if content, ok := s[url]; ok {
		return content, nil
	}

	return nil, errors.New("not found")
}

func catalogOf(manifests ...object) object {
	return object{
		"specVersion": "1.0",
		"host":        object{"displayName": "Acme"},
		"entries": []object{{
			"identifier":     artifactID,
			"type":           artifactType,
			"url":            artifactURL,
			"digest":         digest(artifact),
			"trustManifests": manifests,
		}},
	}
}

func run(t *testing.T, document object, fetcher validate.Fetcher, opts ...validate.Option) *validate.Verification {
	t.Helper()

	result, err := validate.Verify(context.Background(), marshal(t, document), fetcher, opts...)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	return result
}

func TestVerify_PublisherEndorsementMakesCatalogTrusted(t *testing.T) {
	acme := newParty(t, "acme.com")
	result := run(t, catalogOf(acme.endorse(t)), newSite(t, acme), clock(t, now))
	entry := result.Entries[0]

	if !entry.Manifests[0].Signature.Verified() || !entry.Manifests[0].Release.Verified() || !entry.Artifact.Verified() {
		t.Errorf("checks = %+v %+v %+v, want all verified", entry.Manifests[0].Signature, entry.Manifests[0].Release, entry.Artifact)
	}

	if !entry.PublisherEndorsed || result.ConformanceLevel != validate.Trusted {
		t.Errorf("endorsed=%t level=%v, want Trusted", entry.PublisherEndorsed, result.ConformanceLevel)
	}
}

func TestVerify_AnythingUnverifiedKeepsTheCatalogFromTrusted(t *testing.T) {
	tests := []struct {
		name            string
		change          func(t *testing.T, manifest object, s site) []validate.Option
		publisherFailed bool
	}{
		{"manifest changed after signing", func(_ *testing.T, manifest object, _ site) []validate.Option {
			manifest["trustSchema"] = object{"identifier": "https://example.com/schema", "version": "1"}

			return nil
		}, true},
		{"artifact changed", func(_ *testing.T, _ object, s site) []validate.Option {
			s[artifactURL] = []byte("{}")

			return nil
		}, true},
		{"another key in the DID document", func(t *testing.T, _ object, s site) []validate.Option {
			t.Helper()

			s[didURL] = newParty(t, "acme.com").didDocument(t)

			return nil
		}, true},
		{"signature expired", func(t *testing.T, _ object, _ site) []validate.Option {
			t.Helper()

			return []validate.Option{clock(t, "2027-01-01T00:00:00Z")}
		}, true},
		{"DID document unreachable", func(_ *testing.T, _ object, s site) []validate.Option {
			delete(s, didURL)

			return nil
		}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			acme := newParty(t, "acme.com")
			manifest := acme.endorse(t)
			document, s := catalogOf(manifest), newSite(t, acme)
			opts := append([]validate.Option{clock(t, now)}, tc.change(t, manifest, s)...)

			result := run(t, document, s, opts...)
			entry := result.Entries[0]

			if result.ConformanceLevel != validate.Discoverable || entry.PublisherEndorsed || entry.PublisherFailed != tc.publisherFailed {
				t.Errorf("level=%v endorsed=%t failed=%t, want Discoverable, not endorsed, failed=%t",
					result.ConformanceLevel, entry.PublisherEndorsed, entry.PublisherFailed, tc.publisherFailed)
			}
		})
	}
}

func TestVerify_AssessorEndorsesTheReleaseWithoutBeingThePublisher(t *testing.T) {
	assessor := newParty(t, "assessor.example")
	result := run(t, catalogOf(assessor.endorse(t)), newSite(t, assessor), clock(t, now))
	entry := result.Entries[0]

	if !entry.Manifests[0].Signature.Verified() || !entry.Artifact.Verified() {
		t.Errorf("signature=%+v artifact=%+v, want both verified", entry.Manifests[0].Signature, entry.Artifact)
	}

	if entry.PublisherEndorsed || result.ConformanceLevel != validate.Discoverable {
		t.Errorf("endorsed=%t level=%v, want Discoverable", entry.PublisherEndorsed, result.ConformanceLevel)
	}
}

func TestVerify_CatalogSignatureCoversTheWholeDocument(t *testing.T) {
	acme := newParty(t, "acme.com")
	s := newSite(t, acme)
	signed := acme.sign(t, catalogOf(acme.endorse(t)), "ai-catalog+jws")

	result := run(t, signed, s, clock(t, now))
	if !result.CatalogSignature.Verified() || result.CatalogAuthorized {
		t.Errorf("signature=%+v authorized=%t, want verified and unauthorized", result.CatalogSignature, result.CatalogAuthorized)
	}

	operators := []validate.Option{clock(t, now), validate.WithAuthorizedOperators("did:web:acme.com")}
	if !run(t, signed, s, operators...).CatalogAuthorized {
		t.Error("a listed operator was not authorized")
	}

	signed["host"] = object{"displayName": "Evil"}

	result = run(t, signed, s, operators...)
	if !result.CatalogSignature.Failed() || result.CatalogAuthorized {
		t.Errorf("signature=%+v authorized=%t, want failed and unauthorized", result.CatalogSignature, result.CatalogAuthorized)
	}
}
