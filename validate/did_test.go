// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-go)
// SPDX-License-Identifier: Apache-2.0

package validate

import (
	"encoding/json"
	"testing"
)

const (
	testSigner = "did:web:acme.com"
	testKID    = "did:web:acme.com#key-1"
	testRef    = "#key-1"
)

type testMethod struct {
	ID         string         `json:"id"`
	Controller string         `json:"controller"`
	JWK        map[string]any `json:"publicKeyJwk,omitempty"`
}

type testDocument struct {
	ID              string       `json:"id"`
	Methods         []testMethod `json:"verificationMethod"`
	AssertionMethod []string     `json:"assertionMethod"`
}

func newDocument() testDocument {
	return testDocument{
		ID:              testSigner,
		Methods:         []testMethod{{ID: testRef, Controller: testSigner, JWK: map[string]any{"kty": "EC"}}},
		AssertionMethod: []string{testRef},
	}
}

func encode(t *testing.T, document testDocument) []byte {
	t.Helper()

	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}

	return encoded
}

func TestDIDDocumentURL(t *testing.T) {
	if got, ok := didDocumentURL("did:web:acme.com"); !ok || got != "https://acme.com/.well-known/did.json" {
		t.Errorf("got %q, %t", got, ok)
	}

	for _, did := range []string{
		"did:web:acme.com:agents", "did:web:acme.com%3A8443", "did:web:127.0.0.1", "did:web:Acme.com", "did:key:z6Mk",
	} {
		if _, ok := didDocumentURL(did); ok {
			t.Errorf("%s: accepted", did)
		}
	}
}

func TestSelectKey(t *testing.T) {
	key, err := selectKey(encode(t, newDocument()), testSigner, testKID)
	if err != nil || string(key) != `{"kty":"EC"}` {
		t.Fatalf("key=%s err=%v, want the authorized key", key, err)
	}

	for name, change := range map[string]func(d *testDocument){
		"id":              func(d *testDocument) { d.ID = "did:web:evil.com" },
		"assertionMethod": func(d *testDocument) { d.AssertionMethod = nil },
		"controller":      func(d *testDocument) { d.Methods[0].Controller = "did:web:evil.com" },
		"publicKeyJwk":    func(d *testDocument) { d.Methods[0].JWK = nil },
		"ambiguous":       func(d *testDocument) { d.Methods = append(d.Methods, d.Methods[0]) },
	} {
		document := newDocument()
		change(&document)

		if _, err := selectKey(encode(t, document), testSigner, testKID); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	if _, err := selectKey(encode(t, newDocument()), testSigner, "did:web:acme.com#other"); err == nil {
		t.Error("an unlisted kid was accepted")
	}
}
