// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

// Package validate provides semantic validation and conformance-level
// detection for AI Catalog documents, mirroring the AI Catalog specification's
// Minimal / Discoverable / Trusted conformance levels.
package validate

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/agntcy/ai-catalog-go/catalog"
)

// ConformanceLevel is the AI Catalog conformance level a document satisfies.
type ConformanceLevel int

const (
	// Minimal requires specVersion plus at least the structural rules; a
	// document with errors, or without a host, is classified Minimal.
	Minimal ConformanceLevel = iota

	// Discoverable requires a valid document with a host.
	Discoverable

	// Trusted requires a valid Discoverable document plus at least one trust
	// manifest, where every manifest present carries a signature, a subject,
	// and an issuedAt timestamp.
	Trusted
)

// String returns the lowercase name of the conformance level.
func (l ConformanceLevel) String() string {
	switch l {
	case Minimal:
		return "minimal"
	case Discoverable:
		return "discoverable"
	case Trusted:
		return "trusted"
	default:
		return "unknown"
	}
}

// Diagnostic is a single validation error or warning with a JSON-path-like
// location.
type Diagnostic struct {
	Path    string
	Message string
}

// Result is the outcome of validating an AI Catalog document.
type Result struct {
	// IsValid reports whether the document has no validation errors.
	IsValid bool

	// ConformanceLevel is the highest level the document satisfies.
	ConformanceLevel ConformanceLevel

	// Errors are conformance-breaking problems.
	Errors []Diagnostic

	// Warnings are advisory (SHOULD-level) problems.
	Warnings []Diagnostic
}

// maxNestingDepth is the recommended maximum nesting depth for nested catalogs.
const maxNestingDepth = 4

// maxSupportedMajor is the highest AI Catalog major spec version supported.
const maxSupportedMajor = 1

// specVersionParts is the required number of dot-separated components in a
// specVersion ("Major.Minor").
const specVersionParts = 2

// Validate checks the catalog against the AI Catalog specification rules and
// returns a structured result including the detected conformance level.
func Validate(c *catalog.AICatalog) Result {
	v := &validator{}
	// The root sits at depth 0, so maxNestingDepth nested entries are allowed.
	v.validateCatalog(c, "catalog", 0)

	return Result{
		IsValid:          len(v.errors) == 0,
		ConformanceLevel: detectLevel(c, v.errors),
		Errors:           v.errors,
		Warnings:         v.warnings,
	}
}

// validator accumulates diagnostics while walking a catalog document.
type validator struct {
	errors   []Diagnostic
	warnings []Diagnostic
}

func (v *validator) addError(path, message string) {
	v.errors = append(v.errors, Diagnostic{Path: path, Message: message})
}

func (v *validator) addWarning(path, message string) {
	v.warnings = append(v.warnings, Diagnostic{Path: path, Message: message})
}

func detectLevel(c *catalog.AICatalog, errs []Diagnostic) ConformanceLevel {
	if len(errs) > 0 || c.Host == nil {
		return Minimal
	}

	if isTrusted(c) {
		return Trusted
	}

	return Discoverable
}

// isTrusted requires at least one trust manifest and every manifest present to
// be signed and bound to its artifact. An unsigned manifest is an unverifiable
// claim, so one anywhere in the document holds the catalog at Discoverable.
func isTrusted(c *catalog.AICatalog) bool {
	manifests := collectTrustManifests(c)
	if len(manifests) == 0 {
		return false
	}

	for _, manifest := range manifests {
		if manifest.Signature == "" || manifest.Subject == nil || manifest.IssuedAt == "" {
			return false
		}
	}

	return true
}

func collectTrustManifests(c *catalog.AICatalog) []*catalog.TrustManifest {
	var manifests []*catalog.TrustManifest

	if c.Host != nil && c.Host.TrustManifest != nil {
		manifests = append(manifests, c.Host.TrustManifest)
	}

	for i := range c.Entries {
		if manifest := c.Entries[i].TrustManifest; manifest != nil {
			manifests = append(manifests, manifest)
		}
	}

	return manifests
}

func (v *validator) validateCatalog(c *catalog.AICatalog, path string, depth int) {
	v.validateSpecVersion(c.SpecVersion, path+".specVersion")
	v.validateHost(c.Host, path+".host")
	v.validateExtensionKeys(c.Extensions, path+".extensions")
	v.validateEntryUniqueness(c.Entries, path)

	for i := range c.Entries {
		v.validateEntry(&c.Entries[i], fmt.Sprintf("%s.entries[%d]", path, i), depth)
	}
}

// validateHost enforces the required Host Info members: displayName, and the
// trust manifest rules when a host trust manifest is present.
func (v *validator) validateHost(host *catalog.HostInfo, path string) {
	if host == nil {
		return
	}

	if host.DisplayName == "" {
		v.addError(path+".displayName", "host.displayName is required and must not be empty")
	}

	v.validateTrustManifest(host.TrustManifest, path+".trustManifest")
}

// idVersion is a composite key used to detect duplicate (identifier, version)
// pairs.
type idVersion struct {
	id      string
	version string
}

func (v *validator) validateEntryUniqueness(entries []catalog.CatalogEntry, path string) {
	seenVersioned := make(map[idVersion]bool)
	seenUnversioned := make(map[string]bool)
	versionedIDs := make(map[string]bool)

	for i := range entries {
		entry := &entries[i]
		entryPath := fmt.Sprintf("%s.entries[%d]", path, i)

		if entry.Version != "" {
			v.checkVersionedEntry(entry, entryPath, seenVersioned, seenUnversioned)
			seenVersioned[idVersion{entry.Identifier, entry.Version}] = true
			versionedIDs[entry.Identifier] = true

			continue
		}

		if seenUnversioned[entry.Identifier] || versionedIDs[entry.Identifier] {
			v.addError(entryPath, fmt.Sprintf(
				"duplicate identifier %q without version differentiation", entry.Identifier))
		}

		seenUnversioned[entry.Identifier] = true
	}
}

func (v *validator) checkVersionedEntry(
	entry *catalog.CatalogEntry,
	path string,
	seenVersioned map[idVersion]bool,
	seenUnversioned map[string]bool,
) {
	if seenUnversioned[entry.Identifier] {
		v.addError(path+".identifier", fmt.Sprintf(
			"identifier %q cannot appear with and without version", entry.Identifier))
	}

	if seenVersioned[idVersion{entry.Identifier, entry.Version}] {
		v.addError(path, fmt.Sprintf(
			"duplicate (identifier, version) pair: (%q, %q)", entry.Identifier, entry.Version))
	}
}

func (v *validator) validateEntry(entry *catalog.CatalogEntry, path string, depth int) {
	v.validateRequiredEntryFields(entry, path)
	v.validateArtifactSource(entry, path)
	v.validateUpdatedAt(entry, path)
	v.validateExtensionKeys(entry.Extensions, path+".extensions")
	v.validatePublisher(entry.Publisher, path+".publisher")
	v.validateEntryTrust(entry, path)
	v.validateNestedCatalog(entry, path, depth)

	if entry.Identifier != "" && !strings.Contains(entry.Identifier, ":") {
		v.addWarning(path+".identifier", "identifier SHOULD be a URN or URI")
	}
}

// validateRequiredEntryFields checks identifier and type; the url/data
// requirement is handled by validateArtifactSource.
func (v *validator) validateRequiredEntryFields(entry *catalog.CatalogEntry, path string) {
	if entry.Identifier == "" {
		v.addError(path+".identifier", "identifier is required and must not be empty")
	}

	if entry.Type == "" {
		v.addError(path+".type", "type is required and must not be empty")
	}
}

// validatePublisher requires identifier and displayName when a publisher is set.
func (v *validator) validatePublisher(publisher *catalog.Publisher, path string) {
	if publisher == nil {
		return
	}

	if publisher.Identifier == "" {
		v.addError(path+".identifier", "publisher.identifier is required and must not be empty")
	}

	if publisher.DisplayName == "" {
		v.addError(path+".displayName", "publisher.displayName is required and must not be empty")
	}
}

func (v *validator) validateArtifactSource(entry *catalog.CatalogEntry, path string) {
	hasURL := entry.URL != ""
	hasData := len(entry.Data) > 0

	switch {
	case hasURL && hasData:
		v.addError(path, "entry must have exactly one of 'url' or 'data', found both")
	case !hasURL && !hasData:
		v.addError(path, "entry must have exactly one of 'url' or 'data'")
	}
}

func (v *validator) validateUpdatedAt(entry *catalog.CatalogEntry, path string) {
	if entry.UpdatedAt == "" {
		return
	}

	if _, err := time.Parse(time.RFC3339, entry.UpdatedAt); err != nil {
		v.addError(path+".updatedAt", fmt.Sprintf(
			"updatedAt is not a valid RFC 3339 datetime: %q", entry.UpdatedAt))
	}
}

// validateTrustManifest checks the rules that hold for a trust manifest
// wherever it appears in a document.
func (v *validator) validateTrustManifest(manifest *catalog.TrustManifest, path string) {
	if manifest == nil {
		return
	}

	v.validateExtensionKeys(manifest.Extensions, path+".extensions")

	if manifest.Identity == "" {
		v.addError(path+".identity", "trustManifest.identity is required and must not be empty")
	}

	// An empty manifest advertises trust metadata that is not there; the spec
	// requires omitting it instead.
	if !isSubstantive(manifest) {
		v.addError(path, "trustManifest must carry at least one substantive member "+
			"(a signature with its subject and issuedAt, a non-empty attestations or "+
			"provenance array, or a trustSchema) and must otherwise be omitted entirely")
	}

	v.validateSignedManifestMembers(manifest, path)
	v.validateManifestTimestamps(manifest, path)
	v.validateSubject(manifest.Subject, path+".subject")
}

// isSubstantive reports whether a manifest carries verifiable trust evidence.
// A subject and issuedAt count only alongside a signature; unsigned, whoever
// controls the document can set them at will.
func isSubstantive(manifest *catalog.TrustManifest) bool {
	signed := manifest.Signature != "" && manifest.Subject != nil && manifest.IssuedAt != ""

	return signed ||
		len(manifest.Attestations) > 0 ||
		len(manifest.Provenance) > 0 ||
		manifest.TrustSchema != nil
}

// validateSignedManifestMembers enforces the members a signature must commit
// to. Without them the signature covers no artifact and can be replayed onto
// unrelated content.
func (v *validator) validateSignedManifestMembers(manifest *catalog.TrustManifest, path string) {
	if manifest.Signature == "" {
		return
	}

	if manifest.Subject == nil {
		v.addError(path+".subject",
			"a trustManifest carrying a signature must include a subject")
	}

	if manifest.IssuedAt == "" {
		v.addError(path+".issuedAt",
			"a trustManifest carrying a signature must include issuedAt")
	}
}

func (v *validator) validateManifestTimestamps(manifest *catalog.TrustManifest, path string) {
	if manifest.IssuedAt != "" {
		if _, err := time.Parse(time.RFC3339, manifest.IssuedAt); err != nil {
			v.addError(path+".issuedAt", fmt.Sprintf(
				"issuedAt is not a valid RFC 3339 datetime: %q", manifest.IssuedAt))
		}
	}

	if manifest.ExpiresAt == "" {
		return
	}

	expiresAt, err := time.Parse(time.RFC3339, manifest.ExpiresAt)
	if err != nil {
		v.addError(path+".expiresAt", fmt.Sprintf(
			"expiresAt is not a valid RFC 3339 datetime: %q", manifest.ExpiresAt))

		return
	}

	if expiresAt.Before(time.Now()) {
		v.addWarning(path+".expiresAt", fmt.Sprintf(
			"trustManifest expired at %q and SHOULD be rejected", manifest.ExpiresAt))
	}
}

func (v *validator) validateSubject(subject *catalog.Subject, path string) {
	if subject == nil {
		return
	}

	if subject.Type == "" {
		v.addError(path+".type", "subject.type is required and must not be empty")
	}

	if subject.Digest == "" {
		v.addError(path+".digest", "subject.digest is required and must not be empty")
	}
}

// validateSubjectBinding enforces that a subject restates the entry's own type
// and url. That duplication is what pulls those values into the signed payload;
// a mismatch means the entry points at a different artifact than was signed.
func (v *validator) validateSubjectBinding(entry *catalog.CatalogEntry, path string) {
	subject := entry.TrustManifest.Subject
	if subject == nil {
		return
	}

	if subject.Type != "" && entry.Type != "" && subject.Type != entry.Type {
		v.addError(path+".subject.type", fmt.Sprintf(
			"subject.type %q must equal the entry type %q", subject.Type, entry.Type))
	}

	if subject.URL != "" && subject.URL != entry.URL {
		v.addError(path+".subject.url", fmt.Sprintf(
			"subject.url %q must equal the entry url %q", subject.URL, entry.URL))
	}
}

func (v *validator) validateEntryTrust(entry *catalog.CatalogEntry, path string) {
	manifest := entry.TrustManifest
	if manifest == nil {
		return
	}

	v.validateTrustManifest(manifest, path+".trustManifest")
	v.validateSubjectBinding(entry, path+".trustManifest")
	v.validateIdentityBinding(entry, path+".trustManifest")
}

// validateIdentityBinding checks the manifest identity against the entry it
// describes. The two bind by domain alignment rather than exact equality: a
// did:web identity may vouch for a urn:air identifier from the same publisher.
func (v *validator) validateIdentityBinding(entry *catalog.CatalogEntry, path string) {
	identity := entry.TrustManifest.Identity

	aligned, applies := catalog.IdentityBindsToEntry(entry.Identifier, identity)
	if identity == "" || !applies || aligned {
		return
	}

	publisherDomain, _ := catalog.PublisherDomain(entry.Identifier)

	if identityDomain, ok := catalog.IdentityDomain(identity); ok {
		v.addError(path+".identity", fmt.Sprintf(
			"trustManifest.identity domain %q does not align with the entry identifier publisher domain %q",
			identityDomain, publisherDomain))

		return
	}

	v.addError(path+".identity", fmt.Sprintf(
		"trustManifest.identity %q has no trust domain to align with the entry identifier publisher domain %q",
		identity, publisherDomain))
}

func (v *validator) validateNestedCatalog(entry *catalog.CatalogEntry, path string, depth int) {
	if !entry.IsNestedCatalog() {
		return
	}

	if depth >= maxNestingDepth {
		v.addError(path, fmt.Sprintf(
			"nested catalog depth exceeds recommended limit of %d", maxNestingDepth))

		return
	}

	if len(entry.Data) == 0 {
		return
	}

	nested, err := catalog.Parse(entry.Data)
	if err != nil {
		v.addError(path+".data", fmt.Sprintf(
			"nested catalog data is not a valid AI Catalog: %v", err))

		return
	}

	v.validateCatalog(nested, path+".data", depth+1)
}

// reverseDNSKey matches a reverse-DNS extension key such as
// "com.example.confidenceScore": dot-separated labels of alphanumerics and
// inner hyphens.
var reverseDNSKey = regexp.MustCompile(
	`^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$`)

// validateExtensionKeys requires every key to be a URL or a reverse-DNS string,
// the namespacing rule that keeps independent publishers from colliding.
func (v *validator) validateExtensionKeys(extensions map[string]json.RawMessage, path string) {
	for _, key := range slices.Sorted(maps.Keys(extensions)) {
		if isExtensionKey(key) {
			continue
		}

		v.addError(path, fmt.Sprintf(
			"extension key %q must be a valid URL or a reverse-DNS string", key))
	}
}

func isExtensionKey(key string) bool {
	if parsed, err := url.Parse(key); err == nil && parsed.Scheme != "" && parsed.Host != "" {
		return true
	}

	return reverseDNSKey.MatchString(key)
}

func (v *validator) validateSpecVersion(specVersion, path string) {
	if specVersion == "" {
		v.addError(path, "specVersion must not be empty")

		return
	}

	parts := strings.Split(specVersion, ".")
	if len(parts) != specVersionParts {
		v.addError(path, fmt.Sprintf(
			"specVersion must be in Major.Minor format (e.g., '1.0'), found %q", specVersion))

		return
	}

	major, majorErr := strconv.Atoi(parts[0])
	_, minorErr := strconv.Atoi(parts[1])

	if majorErr != nil || minorErr != nil || major < 0 {
		v.addError(path, fmt.Sprintf(
			"specVersion major and minor components must be non-negative integers, found %q",
			specVersion))

		return
	}

	if major > maxSupportedMajor {
		v.addError(path, fmt.Sprintf(
			"unsupported specVersion major version: %d (this implementation supports major version %d)",
			major, maxSupportedMajor))
	}
}
