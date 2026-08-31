// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-go)
// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

// Package trust provides trust-manifest analysis, digest parsing and
// verification, and JCS (RFC 8785) canonicalization for AI Catalog documents.
package trust

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/Agent-Card/ai-catalog-go/catalog"
)

// Digest-parsing errors. Callers may test for these with errors.Is.
var (
	// ErrInvalidDigestFormat indicates a digest that is not "algorithm:hex".
	ErrInvalidDigestFormat = errors.New("digest must use the format 'algorithm:hex-value'")

	// ErrUnsupportedDigestAlgorithm indicates an unrecognized digest algorithm.
	ErrUnsupportedDigestAlgorithm = errors.New("unsupported digest algorithm")

	// ErrWeakDigestAlgorithm indicates a digest algorithm weaker than SHA-256.
	ErrWeakDigestAlgorithm = errors.New("digest algorithm is weaker than SHA-256")

	// ErrInvalidDigestHex indicates a digest whose value is not lowercase hex
	// of the length its algorithm requires.
	ErrInvalidDigestHex = errors.New("invalid digest hex value")
)

// Severity classifies a trust finding.
type Severity int

const (
	// SeverityError is a MUST-level violation.
	SeverityError Severity = iota

	// SeverityWarning is a SHOULD-level advisory.
	SeverityWarning
)

// String returns the lowercase name of the severity.
func (s Severity) String() string {
	switch s {
	case SeverityError:
		return "error"
	case SeverityWarning:
		return "warning"
	default:
		return "unknown"
	}
}

// Finding is a single trust-analysis observation.
type Finding struct {
	Severity Severity
	Path     string
	Message  string
}

// ManifestReport summarizes the analysis of a single trust manifest.
type ManifestReport struct {
	Path     string
	Identity string

	// HasSignature and HasSubject are both required for the manifest to be
	// bound to specific artifact bytes.
	HasSignature bool
	HasSubject   bool

	AttestationCount int
	ProvenanceCount  int
	Findings         []Finding
}

// CatalogTrustReport aggregates trust analysis across a catalog document, its
// host, and its entries.
type CatalogTrustReport struct {
	// Findings is the combined list of catalog, host, and entry findings.
	Findings []Finding

	// HasSignature reports whether the document carries a top-level signature.
	HasSignature bool

	// Host is the host manifest report, or nil when the host has no manifest.
	Host *ManifestReport

	// Entries holds one report per entry that carries a trust manifest.
	Entries []ManifestReport
}

// jwsParts is the number of dot-separated components in a JWS compact
// serialization (header, payload, signature).
const jwsParts = 3

// ParsedDigest is a validated "algorithm:hex" digest.
type ParsedDigest struct {
	algorithm string
	hexValue  string
}

// Algorithm returns the normalized (lowercased) digest algorithm.
func (d *ParsedDigest) Algorithm() string { return d.algorithm }

// HexValue returns the normalized (lowercased) hex digest value.
func (d *ParsedDigest) HexValue() string { return d.hexValue }

// Hex lengths of the accepted digest algorithms (two hex chars per byte).
const (
	sha256HexLen = 64
	sha384HexLen = 96
	sha512HexLen = 128
)

// ParseDigest parses and validates a digest string of the form
// "algorithm:hex-value". Only SHA-256, SHA-384, and SHA-512 are accepted;
// weaker algorithms are rejected.
func ParseDigest(value string) (*ParsedDigest, error) {
	algorithm, hexValue, found := strings.Cut(value, ":")
	if !found || algorithm == "" || hexValue == "" || strings.Count(value, ":") != 1 {
		return nil, fmt.Errorf("%w, found %q", ErrInvalidDigestFormat, value)
	}

	normalized := strings.ToLower(algorithm)

	var expectedLen int

	switch normalized {
	case "sha256":
		expectedLen = sha256HexLen
	case "sha384":
		expectedLen = sha384HexLen
	case "sha512":
		expectedLen = sha512HexLen
	case "md5", "sha1", "sha224":
		return nil, fmt.Errorf("%w: %q", ErrWeakDigestAlgorithm, normalized)
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedDigestAlgorithm, normalized)
	}

	if len(hexValue) != expectedLen {
		return nil, fmt.Errorf("%w: %s requires %d hex characters, found %d",
			ErrInvalidDigestHex, normalized, expectedLen, len(hexValue))
	}

	if _, err := hex.DecodeString(hexValue); err != nil {
		return nil, fmt.Errorf("%w: %q contains non-hex characters",
			ErrInvalidDigestHex, hexValue)
	}

	return &ParsedDigest{algorithm: normalized, hexValue: strings.ToLower(hexValue)}, nil
}

// VerifyBytes reports whether the digest matches the SHA sum of data.
func (d *ParsedDigest) VerifyBytes(data []byte) bool {
	var sum []byte

	switch d.algorithm {
	case "sha256":
		digest := sha256.Sum256(data)
		sum = digest[:]
	case "sha384":
		digest := sha512.Sum384(data)
		sum = digest[:]
	case "sha512":
		digest := sha512.Sum512(data)
		sum = digest[:]
	default:
		return false
	}

	return hex.EncodeToString(sum) == d.hexValue
}

// VerifyDigest parses expectedDigest and reports whether it matches data. It
// returns an error only when expectedDigest is malformed.
func VerifyDigest(expectedDigest string, data []byte) (bool, error) {
	parsed, err := ParseDigest(expectedDigest)
	if err != nil {
		return false, err
	}

	return parsed.VerifyBytes(data), nil
}

// AnalyzeCatalog inspects a catalog's own signature and the trust manifests on
// its host and entries, and returns a report of findings.
func AnalyzeCatalog(c *catalog.AICatalog) CatalogTrustReport {
	var report CatalogTrustReport

	if c.Signature != "" {
		report.HasSignature = true
		report.Findings = analyzeCatalogSignature(c.Signature, report.Findings)
	}

	if c.Host != nil {
		if hostReport := analyzeHostManifest(c.Host); hostReport != nil {
			report.Host = hostReport
			report.Findings = append(report.Findings, hostReport.Findings...)
		}
	}

	for i := range c.Entries {
		if entryReport := analyzeEntryManifest(&c.Entries[i], i); entryReport != nil {
			report.Entries = append(report.Entries, *entryReport)
			report.Findings = append(report.Findings, entryReport.Findings...)
		}
	}

	return report
}

// analyzeCatalogSignature checks the document's own signature, which covers the
// catalog with its "signature" member removed. See CanonicalizeForSignature.
func analyzeCatalogSignature(signature string, findings []Finding) []Finding {
	const path = "catalog.signature"

	if !looksLikeDetachedJWS(signature) {
		return append(findings, Finding{
			Severity: SeverityError,
			Path:     path,
			Message:  "signature must use detached JWS compact serialization",
		})
	}

	return analyzeSignatureAlgorithm(path, signature, findings)
}

func analyzeHostManifest(host *catalog.HostInfo) *ManifestReport {
	manifest := host.TrustManifest
	if manifest == nil {
		return nil
	}

	path := "catalog.host.trustManifest"

	var findings []Finding

	if !strings.Contains(manifest.Identity, ":") {
		findings = append(findings, Finding{
			Severity: SeverityWarning,
			Path:     path + ".identity",
			Message:  "trust manifest identity SHOULD be a URI-like identifier",
		})
	}

	if host.Identifier != "" && manifest.Identity != host.Identifier {
		findings = append(findings, Finding{
			Severity: SeverityWarning,
			Path:     path + ".identity",
			Message: fmt.Sprintf(
				"host trustManifest.identity '%s' SHOULD match host.identifier '%s'",
				manifest.Identity, host.Identifier),
		})
	}

	findings = analyzeManifestContents(path, manifest, findings)

	return newManifestReport(path, manifest, findings)
}

func analyzeEntryManifest(entry *catalog.CatalogEntry, index int) *ManifestReport {
	manifest := entry.TrustManifest
	if manifest == nil {
		return nil
	}

	path := fmt.Sprintf("catalog.entries[%d].trustManifest", index)

	var findings []Finding

	// Identity binds by domain alignment, not exact equality.
	if aligned, applies := catalog.IdentityBindsToEntry(
		entry.Identifier, manifest.Identity); applies && !aligned {
		publisherDomain, _ := catalog.PublisherDomain(entry.Identifier)

		var message string
		if identityDomain, ok := catalog.IdentityDomain(manifest.Identity); ok {
			message = fmt.Sprintf(
				"trustManifest.identity domain '%s' MUST align with entry identifier publisher domain '%s'",
				identityDomain, publisherDomain)
		} else {
			message = fmt.Sprintf(
				"trustManifest.identity '%s' MUST carry a trust domain aligned with entry identifier publisher domain '%s'",
				manifest.Identity, publisherDomain)
		}

		findings = append(findings, Finding{
			Severity: SeverityError,
			Path:     path + ".identity",
			Message:  message,
		})
	}

	if !strings.Contains(manifest.Identity, ":") {
		findings = append(findings, Finding{
			Severity: SeverityWarning,
			Path:     path + ".identity",
			Message:  "trust manifest identity SHOULD be a URI-like identifier",
		})
	}

	findings = analyzeManifestContents(path, manifest, findings)

	return newManifestReport(path, manifest, findings)
}

func newManifestReport(path string, manifest *catalog.TrustManifest, findings []Finding) *ManifestReport {
	return &ManifestReport{
		Path:             path,
		Identity:         manifest.Identity,
		HasSignature:     manifest.Signature != "",
		HasSubject:       manifest.Subject != nil,
		AttestationCount: len(manifest.Attestations),
		ProvenanceCount:  len(manifest.Provenance),
		Findings:         findings,
	}
}

func analyzeManifestContents(path string, manifest *catalog.TrustManifest, findings []Finding) []Finding {
	findings = analyzeSignature(path, manifest, findings)
	findings = analyzeSubject(path, manifest.Subject, findings)
	findings = analyzeValidityWindow(path, manifest, findings)
	findings = analyzeTrustSchema(path, manifest.TrustSchema, findings)
	findings = analyzeAttestations(path, manifest.Attestations, findings)
	findings = analyzeProvenance(path, manifest.Provenance, findings)

	return findings
}

func analyzeSignature(path string, manifest *catalog.TrustManifest, findings []Finding) []Finding {
	if manifest.Signature == "" {
		return findings
	}

	if !looksLikeDetachedJWS(manifest.Signature) {
		findings = append(findings, Finding{
			Severity: SeverityError,
			Path:     path + ".signature",
			Message:  "signature must use detached JWS compact serialization",
		})

		return findings
	}

	// Without a subject the signature covers no artifact and can be lifted onto
	// unrelated content.
	if manifest.Subject == nil {
		findings = append(findings, Finding{
			Severity: SeverityError,
			Path:     path + ".subject",
			Message:  "a signed trust manifest must carry a subject binding it to the artifact",
		})
	}

	if manifest.IssuedAt == "" {
		findings = append(findings, Finding{
			Severity: SeverityError,
			Path:     path + ".issuedAt",
			Message:  "a signed trust manifest must carry an issuedAt timestamp",
		})
	}

	return analyzeSignatureAlgorithm(path+".signature", manifest.Signature, findings)
}

func analyzeSignatureAlgorithm(path, signature string, findings []Finding) []Finding {
	algorithm, ok := jwsAlgorithm(signature)
	if !ok {
		return append(findings, Finding{
			Severity: SeverityError,
			Path:     path,
			Message:  "signature JWS header must be base64url-encoded JSON declaring an 'alg'",
		})
	}

	switch {
	case isForbiddenJWSAlgorithm(algorithm):
		return append(findings, Finding{
			Severity: SeverityError,
			Path:     path,
			Message: fmt.Sprintf(
				"signature algorithm '%s' must be rejected; a trust manifest requires an asymmetric signature",
				algorithm),
		})
	case !slices.Contains(allowedJWSAlgorithms, algorithm):
		return append(findings, Finding{
			Severity: SeverityWarning,
			Path:     path,
			Message: fmt.Sprintf(
				"signature algorithm '%s' is outside the specification allowlist (%s)",
				algorithm, strings.Join(allowedJWSAlgorithms, ", ")),
		})
	}

	return findings
}

func analyzeSubject(path string, subject *catalog.Subject, findings []Finding) []Finding {
	if subject == nil {
		return findings
	}

	base := path + ".subject"

	if subject.Type == "" {
		findings = append(findings, Finding{
			Severity: SeverityError,
			Path:     base + ".type",
			Message:  "subject type must not be empty",
		})
	}

	if subject.Digest == "" {
		findings = append(findings, Finding{
			Severity: SeverityError,
			Path:     base + ".digest",
			Message:  "subject digest must not be empty",
		})

		return findings
	}

	return analyzeDigestField(subject.Digest, base+".digest", findings)
}

func analyzeValidityWindow(path string, manifest *catalog.TrustManifest, findings []Finding) []Finding {
	if manifest.IssuedAt != "" {
		if _, err := time.Parse(time.RFC3339, manifest.IssuedAt); err != nil {
			findings = append(findings, invalidTimestamp(path+".issuedAt", manifest.IssuedAt))
		}
	}

	if manifest.ExpiresAt == "" {
		return findings
	}

	expiresAt, err := time.Parse(time.RFC3339, manifest.ExpiresAt)
	if err != nil {
		return append(findings, invalidTimestamp(path+".expiresAt", manifest.ExpiresAt))
	}

	if expiresAt.Before(time.Now()) {
		return append(findings, Finding{
			Severity: SeverityWarning,
			Path:     path + ".expiresAt",
			Message: fmt.Sprintf(
				"trust manifest expired at %s and SHOULD be rejected", manifest.ExpiresAt),
		})
	}

	return findings
}

func invalidTimestamp(path, value string) Finding {
	return Finding{
		Severity: SeverityError,
		Path:     path,
		Message:  fmt.Sprintf("%q is not a valid RFC 3339 datetime", value),
	}
}

func analyzeTrustSchema(path string, schema *catalog.TrustSchema, findings []Finding) []Finding {
	if schema == nil {
		return findings
	}

	if schema.Identifier == "" {
		findings = append(findings, Finding{
			Severity: SeverityError,
			Path:     path + ".trustSchema.identifier",
			Message:  "trustSchema.identifier must not be empty",
		})
	}

	if schema.Version == "" {
		findings = append(findings, Finding{
			Severity: SeverityError,
			Path:     path + ".trustSchema.version",
			Message:  "trustSchema.version must not be empty",
		})
	}

	return findings
}

func analyzeAttestations(path string, attestations []catalog.Attestation, findings []Finding) []Finding {
	for i := range attestations {
		attestation := &attestations[i]
		base := fmt.Sprintf("%s.attestations[%d]", path, i)

		if attestation.Type == "" {
			findings = append(findings, Finding{
				Severity: SeverityError,
				Path:     base + ".type",
				Message:  "attestation type must not be empty",
			})
		}

		if attestation.URI == "" {
			findings = append(findings, Finding{
				Severity: SeverityError,
				Path:     base + ".uri",
				Message:  "attestation uri must not be empty",
			})
		}

		if attestation.Digest != "" {
			findings = analyzeDigestField(attestation.Digest, base+".digest", findings)
		}
	}

	return findings
}

func analyzeProvenance(path string, provenance []catalog.ProvenanceLink, findings []Finding) []Finding {
	for i := range provenance {
		link := &provenance[i]
		base := fmt.Sprintf("%s.provenance[%d]", path, i)

		if link.Relation == "" {
			findings = append(findings, Finding{
				Severity: SeverityError,
				Path:     base + ".relation",
				Message:  "provenance relation must not be empty",
			})
		}

		if link.SourceID == "" {
			findings = append(findings, Finding{
				Severity: SeverityError,
				Path:     base + ".sourceId",
				Message:  "provenance sourceId must not be empty",
			})
		}

		if link.SourceDigest != "" {
			findings = analyzeDigestField(link.SourceDigest, base+".sourceDigest", findings)
		}
	}

	return findings
}

func analyzeDigestField(value, path string, findings []Finding) []Finding {
	if _, err := ParseDigest(value); err != nil {
		findings = append(findings, Finding{
			Severity: SeverityError,
			Path:     path,
			Message:  err.Error(),
		})
	}

	return findings
}

// looksLikeDetachedJWS reports whether signature is a detached JWS compact
// serialization: a non-empty header, an empty payload, and a non-empty
// signature, separated by dots.
func looksLikeDetachedJWS(signature string) bool {
	parts := strings.Split(signature, ".")
	if len(parts) != jwsParts {
		return false
	}

	return parts[0] != "" && parts[1] == "" && parts[2] != ""
}

// allowedJWSAlgorithms is the spec's signature algorithm allowlist: the
// asymmetric algorithms producers must use and consumers must support.
var allowedJWSAlgorithms = []string{"ES256", "ES384", "EdDSA", "PS256", "PS384", "RS256"}

// isForbiddenJWSAlgorithm reports whether algorithm cannot establish
// third-party trust: "none" carries no proof, and the HMAC family only proves
// possession of a shared secret. Matched case-insensitively.
func isForbiddenJWSAlgorithm(algorithm string) bool {
	normalized := strings.ToUpper(algorithm)

	return normalized == "NONE" || strings.HasPrefix(normalized, "HS")
}

// jwsAlgorithm returns the "alg" declared by a JWS compact serialization's
// protected header.
func jwsAlgorithm(signature string) (string, bool) {
	encoded, _, _ := strings.Cut(signature, ".")

	header, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return "", false
	}

	var parsed struct {
		Algorithm string `json:"alg"`
	}

	if err := json.Unmarshal(header, &parsed); err != nil || parsed.Algorithm == "" {
		return "", false
	}

	return parsed.Algorithm, true
}
