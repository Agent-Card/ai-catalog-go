// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

// Package trust provides trust-manifest analysis, digest parsing and
// verification, and JCS-style canonicalization for AI Catalog documents.
package trust

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/agntcy/ai-catalog-go-sdk/catalog"
)

// Digest-parsing errors. Callers may test for these with errors.Is.
var (
	// ErrInvalidDigestFormat indicates a digest that is not "algorithm:hex".
	ErrInvalidDigestFormat = errors.New("digest must use the format 'algorithm:hex-value'")

	// ErrUnsupportedDigestAlgorithm indicates an unrecognized digest algorithm.
	ErrUnsupportedDigestAlgorithm = errors.New("unsupported digest algorithm")

	// ErrWeakDigestAlgorithm indicates a digest algorithm weaker than SHA-256.
	ErrWeakDigestAlgorithm = errors.New("digest algorithm is weaker than SHA-256")

	// ErrInvalidDigestHex indicates a digest whose value is not valid hex.
	ErrInvalidDigestHex = errors.New("digest hex value contains non-hex characters")
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
	Path             string
	Identity         string
	HasSignature     bool
	AttestationCount int
	ProvenanceCount  int
	Findings         []Finding
}

// CatalogTrustReport aggregates trust analysis across a catalog's host and
// entries.
type CatalogTrustReport struct {
	// Findings is the combined list of host and entry findings.
	Findings []Finding

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
		return nil, ErrInvalidDigestHex
	}

	if _, err := hex.DecodeString(hexValue); err != nil {
		return nil, ErrInvalidDigestHex
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

// CanonicalizeTrustManifest returns the canonical JSON form of a trust manifest
// (recursively key-sorted, with the "signature" field removed) suitable for
// signing or signature verification.
func CanonicalizeTrustManifest(manifest *catalog.TrustManifest) (string, error) {
	raw, err := json.Marshal(manifest)
	if err != nil {
		return "", fmt.Errorf("marshal trust manifest: %w", err)
	}

	// UseNumber preserves exact integer metadata values across the round-trip.
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()

	var value any
	if err := dec.Decode(&value); err != nil {
		return "", fmt.Errorf("decode trust manifest: %w", err)
	}

	if object, ok := value.(map[string]any); ok {
		delete(object, "signature")
	}

	// encoding/json sorts map keys at every level, yielding JCS-style ordering.
	canonical, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("marshal canonical trust manifest: %w", err)
	}

	return string(canonical), nil
}

// AnalyzeCatalog inspects the trust manifests on a catalog's host and entries
// and returns a report of findings.
func AnalyzeCatalog(c *catalog.AICatalog) CatalogTrustReport {
	var report CatalogTrustReport

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

	// Identity binds to the entry by domain alignment, not exact equality.
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
		AttestationCount: len(manifest.Attestations),
		ProvenanceCount:  len(manifest.Provenance),
		Findings:         findings,
	}
}

func analyzeManifestContents(path string, manifest *catalog.TrustManifest, findings []Finding) []Finding {
	if manifest.Signature != "" && !looksLikeDetachedJWS(manifest.Signature) {
		findings = append(findings, Finding{
			Severity: SeverityError,
			Path:     path + ".signature",
			Message:  "signature must use detached JWS compact serialization",
		})
	}

	findings = analyzeTrustSchema(path, manifest.TrustSchema, findings)
	findings = analyzeAttestations(path, manifest.Attestations, findings)
	findings = analyzeProvenance(path, manifest.Provenance, findings)

	return findings
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
