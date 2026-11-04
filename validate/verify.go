// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-go)
// SPDX-License-Identifier: Apache-2.0

package validate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/Agent-Card/ai-catalog-go/catalog"
	"github.com/Agent-Card/ai-catalog-go/internal/identity"
	"github.com/Agent-Card/ai-catalog-go/internal/jws"
	"github.com/Agent-Card/ai-catalog-go/trust"
)

// Fetcher fetches DID documents and artifacts. Implementations must follow the
// specification's safe fetching rules: https only, no private addresses, size
// and time limits.
type Fetcher interface {
	Fetch(ctx context.Context, url string) ([]byte, error)
}

// FetcherFunc adapts a function to a Fetcher.
type FetcherFunc func(ctx context.Context, url string) ([]byte, error)

// Fetch calls f.
func (f FetcherFunc) Fetch(ctx context.Context, url string) ([]byte, error) { return f(ctx, url) }

// Status is the result of one check.
type Status string

// The results of a check.
const (
	StatusVerified Status = "verified"
	StatusFailed   Status = "failed"

	// StatusUnverifiable means the check could not run: a fetch failed or the
	// profile is unsupported.
	StatusUnverifiable Status = "unverifiable"
)

// Outcome is the result of one check, with the reason when it did not verify.
type Outcome struct {
	Status Status
	Reason string
}

// Verified reports whether the check passed.
func (o *Outcome) Verified() bool { return o != nil && o.Status == StatusVerified }

// Failed reports whether the check ran and did not pass.
func (o *Outcome) Failed() bool { return o != nil && o.Status == StatusFailed }

// ManifestTrust is the verification of one trust manifest of an entry.
type ManifestTrust struct {
	Index       int
	Contributor string

	// Signer is empty when the manifest is unsigned.
	Signer string

	// Signature and Release are nil when the manifest is unsigned.
	Signature *Outcome
	Release   *Outcome

	// Publisher reports whether the signer is the publisher the entry names.
	Publisher bool
}

func (m *ManifestTrust) accepted() bool { return m.Signature.Verified() && m.Release.Verified() }

func (m *ManifestTrust) failed() bool { return m.Signature.Failed() || m.Release.Failed() }

// EntryTrust is the verification of one root entry.
type EntryTrust struct {
	Index      int
	Identifier string
	Manifests  []ManifestTrust

	// Artifact is checked only when a manifest is accepted for the entry.
	Artifact *Outcome

	PublisherEndorsed bool
	PublisherFailed   bool
}

// Verification is the result of Verify.
type Verification struct {
	Validation Result

	// ConformanceLevel is Trusted when an entry has a verified publisher
	// endorsement and none fails.
	ConformanceLevel ConformanceLevel

	// CatalogSignature is nil when the catalog is unsigned.
	CatalogSignature  *Outcome
	CatalogAuthorized bool
	Entries           []EntryTrust
}

// rawCatalog holds the parts of the document that signatures and digests cover
// as served, which the model does not keep.
type rawCatalog struct {
	Entries []struct {
		Data           json.RawMessage   `json:"data"`
		TrustManifests []json.RawMessage `json:"trustManifests"`
	} `json:"entries"`
}

// Verify validates the document and verifies the signatures and artifacts of
// its root entries. It reads the document as served, since signatures cover
// members the model does not keep.
func Verify(ctx context.Context, document []byte, fetcher Fetcher, opts ...Option) (*Verification, error) {
	parsed, err := catalog.Parse(document)
	if err != nil {
		return nil, fmt.Errorf("parse catalog: %w", err)
	}

	var raw rawCatalog
	if err := json.Unmarshal(document, &raw); err != nil {
		return nil, fmt.Errorf("parse catalog: %w", err)
	}

	validation := Validate(parsed, opts...)
	cfg := newConfig(opts)
	verifier := &verifier{ctx: ctx, now: cfg.now(), fetcher: fetcher}

	if cfg.baseURL != "" {
		verifier.base, _ = url.Parse(cfg.baseURL)
	}

	result := &Verification{Validation: validation, ConformanceLevel: validation.ConformanceLevel}

	if parsed.Signature != nil {
		result.CatalogSignature = verifier.signature(parsed.Signature, catalogJWSType, document)
		result.CatalogAuthorized = result.CatalogSignature.Verified() &&
			slices.Contains(cfg.operators, parsed.Signature.Signer)
	}

	for i := range parsed.Entries {
		result.Entries = append(result.Entries, verifier.entry(i, &parsed.Entries[i], raw.Entries[i].Data, raw.Entries[i].TrustManifests))
	}

	endorsed := slices.ContainsFunc(result.Entries, func(e EntryTrust) bool { return e.PublisherEndorsed })
	failed := slices.ContainsFunc(result.Entries, func(e EntryTrust) bool { return e.PublisherFailed })

	if endorsed && !failed && validation.ConformanceLevel >= Discoverable {
		result.ConformanceLevel = Trusted
	}

	return result, nil
}

// failure is a check that did not verify.
type failure struct{ outcome Outcome }

func (f *failure) Error() string { return f.outcome.Reason }

func failed(format string, args ...any) error {
	return &failure{Outcome{StatusFailed, fmt.Sprintf(format, args...)}}
}

func unverifiable(format string, args ...any) error {
	return &failure{Outcome{StatusUnverifiable, fmt.Sprintf(format, args...)}}
}

func outcome(err error) *Outcome {
	if err == nil {
		return &Outcome{Status: StatusVerified}
	}

	if f, ok := errors.AsType[*failure](err); ok {
		return &f.outcome
	}

	return &Outcome{StatusFailed, err.Error()}
}

type verifier struct {
	ctx     context.Context //nolint:containedctx // scoped to one Verify call
	now     time.Time
	fetcher Fetcher
	base    *url.URL
}

func (v *verifier) entry(index int, entry *catalog.CatalogEntry, data json.RawMessage, manifests []json.RawMessage) EntryTrust {
	result := EntryTrust{Index: index, Identifier: entry.Identifier}

	for i := range entry.TrustManifests {
		var payload json.RawMessage
		if i < len(manifests) {
			payload = manifests[i]
		}

		result.Manifests = append(result.Manifests, v.manifest(entry, &entry.TrustManifests[i], i, payload))
	}

	if slices.ContainsFunc(result.Manifests, func(m ManifestTrust) bool { return m.accepted() }) {
		result.Artifact = outcome(v.checkArtifact(entry, data))
	}

	publisherAccepted := slices.ContainsFunc(result.Manifests, func(m ManifestTrust) bool { return m.Publisher && m.accepted() })
	result.PublisherEndorsed = publisherAccepted && result.Artifact.Verified()
	result.PublisherFailed = slices.ContainsFunc(result.Manifests, func(m ManifestTrust) bool { return m.Publisher && m.failed() }) ||
		(publisherAccepted && result.Artifact.Failed())

	return result
}

func (v *verifier) manifest(entry *catalog.CatalogEntry, manifest *catalog.TrustManifest, index int, raw []byte) ManifestTrust {
	result := ManifestTrust{Index: index, Contributor: manifest.Contributor}

	signature := manifest.Signature
	if signature == nil {
		return result
	}

	result.Signer = signature.Signer
	result.Signature = v.signature(signature, manifestJWSType, raw)
	result.Release = release(entry, manifest, signature)
	result.Publisher = isPublisher(entry, signature.Signer)

	return result
}

func (v *verifier) signature(signature *catalog.Signature, typ string, document []byte) *Outcome {
	return outcome(v.checkSignature(signature, typ, document))
}

func (v *verifier) checkSignature(signature *catalog.Signature, typ string, document []byte) error {
	if signature.Profile != didWebProfile {
		return unverifiable("the signer profile %q is not supported", signature.Profile)
	}

	header, err := v.checkHeader(signature, typ)
	if err != nil {
		return err
	}

	if err := v.checkTime(signature); err != nil {
		return err
	}

	location, ok := didDocumentURL(signature.Signer)
	if !ok {
		return failed("the signer is not a root did:web DID")
	}

	body, err := v.fetcher.Fetch(v.ctx, location)
	if err != nil {
		return unverifiable("cannot fetch the DID document: %v", err)
	}

	jwk, err := selectKey(body, signature.Signer, header.KeyID)
	if err != nil {
		return failed("%v", err)
	}

	key, err := trust.ParseES256Key(jwk)
	if err != nil {
		return failed("%v", err)
	}

	payload, err := trust.CanonicalizeForSignature(document)
	if err != nil {
		return failed("%v", err)
	}

	if err := trust.VerifyES256(signature.JWS, payload, key); err != nil {
		return failed("%v", err)
	}

	return nil
}

func (v *verifier) checkHeader(signature *catalog.Signature, typ string) (jws.Header, error) {
	if !jws.Detached(signature.JWS) {
		return jws.Header{}, failed("the jws is not a detached compact serialization")
	}

	header, err := jws.Parse(signature.JWS)
	if err != nil {
		return jws.Header{}, failed("the jws header is invalid: %v", err)
	}

	if header.Algorithm != profileAlgorithm {
		return jws.Header{}, failed("the jws algorithm %q is not %s", header.Algorithm, profileAlgorithm)
	}

	if header.Type != typ {
		return jws.Header{}, failed("the jws typ %q is not %q", header.Type, typ)
	}

	for _, member := range keySourceMembers {
		if header.Has(member) {
			return jws.Header{}, failed("the jws header must not contain %q", member)
		}
	}

	if !identity.RootDIDWeb(signature.Signer) {
		return jws.Header{}, failed("the signer is not a root did:web DID")
	}

	fragment, ok := strings.CutPrefix(header.KeyID, signature.Signer+"#")
	if !ok || fragment == "" || strings.ContainsAny(fragment, "/?#") {
		return jws.Header{}, failed("the jws kid %q is not the signer followed by a fragment", header.KeyID)
	}

	return header, nil
}

func (v *verifier) checkTime(signature *catalog.Signature) error {
	issued, ok := instant(signature.IssuedAt)
	if !ok {
		return failed("issuedAt is not an RFC 3339 timestamp")
	}

	if issued.After(v.now) {
		return failed("issued in the future, at %s", signature.IssuedAt)
	}

	if signature.ExpiresAt == "" {
		return nil
	}

	expires, ok := instant(signature.ExpiresAt)
	if !ok {
		return failed("expiresAt is not an RFC 3339 timestamp")
	}

	if !expires.After(v.now) {
		return failed("expired at %s", signature.ExpiresAt)
	}

	return nil
}

func (v *verifier) checkArtifact(entry *catalog.CatalogEntry, data json.RawMessage) error {
	content, err := v.artifactContent(entry, data)
	if err != nil {
		return err
	}

	match, err := trust.VerifyDigest(entry.Digest, content)

	switch {
	case err != nil:
		return failed("%v", err)
	case !match:
		return failed("the content does not match the entry digest")
	default:
		return nil
	}
}

// artifactContent returns the bytes the entry digest covers: the canonical
// form of inline data, or the document at the entry url.
func (v *verifier) artifactContent(entry *catalog.CatalogEntry, data json.RawMessage) ([]byte, error) {
	if len(data) > 0 {
		canonical, err := trust.Canonicalize(data)
		if err != nil {
			return nil, failed("%v", err)
		}

		return canonical, nil
	}

	location, err := v.resolve(entry.URL)
	if err != nil {
		return nil, failed("the entry url is not a URL: %v", err)
	}

	if location.Scheme != "https" {
		return nil, unverifiable("only https artifacts are fetched")
	}

	content, err := v.fetcher.Fetch(v.ctx, location.String())
	if err != nil {
		return nil, unverifiable("cannot fetch the artifact: %v", err)
	}

	return content, nil
}

func (v *verifier) resolve(reference string) (*url.URL, error) {
	parsed, err := url.Parse(reference)
	if err != nil {
		return nil, fmt.Errorf("parse url: %w", err)
	}

	if v.base != nil {
		return v.base.ResolveReference(parsed), nil
	}

	if !parsed.IsAbs() {
		return nil, errors.New("relative URL without a base")
	}

	return parsed, nil
}

// release checks Entry Release Coverage.
func release(entry *catalog.CatalogEntry, manifest *catalog.TrustManifest, signature *catalog.Signature) *Outcome {
	subject := manifest.Subject

	switch {
	case signature.Signer != manifest.Contributor:
		return &Outcome{StatusFailed, "the signer is not the contributor"}
	case entry.Digest == "":
		return &Outcome{StatusFailed, "the entry has no digest"}
	case subject == nil:
		return &Outcome{StatusFailed, "the manifest has no subject"}
	case subject.Identifier == "" || subject.Type == "" || subject.Digest == "":
		return &Outcome{StatusFailed, "the subject is incomplete"}
	}

	if mismatches := subjectMismatches(entry, subject); len(mismatches) > 0 {
		return &Outcome{StatusFailed, mismatches[0].message}
	}

	return &Outcome{Status: StatusVerified}
}
