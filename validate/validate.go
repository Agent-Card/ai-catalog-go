// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-go)
// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

// Package validate checks AI Catalog documents against the specification and
// detects their conformance level (Minimal, Discoverable, Trusted).
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

	"github.com/Agent-Card/ai-catalog-go/catalog"
)

// ConformanceLevel is the AI Catalog conformance level a document satisfies.
type ConformanceLevel int

const (
	// Minimal is a document with errors, or without a host.
	Minimal ConformanceLevel = iota

	// Discoverable is a valid document with a host.
	Discoverable

	// Trusted is a Discoverable document in which every root entry trust
	// manifest is signed, bound to its entry, unexpired and conforms to the
	// did:web Publisher Profile. Signatures are not verified.
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

// Diagnostic is a single validation error or warning.
type Diagnostic struct {
	Code    Code
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

	// Warnings are advisory problems, including did:web profile violations.
	Warnings []Diagnostic
}

const (
	// defaultMaxNestingDepth is the recommended maximum nesting of catalogs.
	defaultMaxNestingDepth = 4

	// maxSupportedMajor is the highest AI Catalog major spec version supported.
	maxSupportedMajor = 1

	// specVersionParts is the number of components in "Major.Minor".
	specVersionParts = 2
)

type config struct {
	now      func() time.Time
	maxDepth int
}

// Option customizes Validate.
type Option func(*config)

// WithClock sets the clock used to decide whether a trust manifest has expired.
func WithClock(now func() time.Time) Option {
	return func(c *config) { c.now = now }
}

// WithMaxNestingDepth sets how deeply catalogs may nest. The default is 4.
func WithMaxNestingDepth(depth int) Option {
	return func(c *config) { c.maxDepth = depth }
}

// Validate checks the catalog against the AI Catalog specification and returns
// the diagnostics and the detected conformance level.
func Validate(c *catalog.AICatalog, opts ...Option) Result {
	v := &validator{cfg: config{now: time.Now, maxDepth: defaultMaxNestingDepth}}

	for _, opt := range opts {
		opt(&v.cfg)
	}

	v.validateCatalog(c, "catalog", 0)

	return Result{
		IsValid:          len(v.errors) == 0,
		ConformanceLevel: v.level(c),
		Errors:           v.errors,
		Warnings:         v.warnings,
	}
}

// validator accumulates diagnostics while walking a catalog document.
type validator struct {
	cfg      config
	errors   []Diagnostic
	warnings []Diagnostic

	// manifests counts the root entry trust manifests; heldBack is set when one
	// of them is not ready to be trusted.
	manifests int
	heldBack  bool
}

func (v *validator) addError(code Code, path, message string) {
	v.errors = append(v.errors, Diagnostic{Code: code, Path: path, Message: message})
}

func (v *validator) addWarning(code Code, path, message string) {
	v.warnings = append(v.warnings, Diagnostic{Code: code, Path: path, Message: message})
}

func (v *validator) level(c *catalog.AICatalog) ConformanceLevel {
	switch {
	case len(v.errors) > 0 || c.Host == nil:
		return Minimal
	case v.manifests > 0 && !v.heldBack:
		return Trusted
	default:
		return Discoverable
	}
}

func (v *validator) validateCatalog(c *catalog.AICatalog, path string, depth int) {
	v.validateSpecVersion(c.SpecVersion, path+".specVersion")
	v.validateHost(c.Host, path+".host")
	v.validateSignature(c.Signature, path+".signature")
	v.validateExtensionKeys(c.Extensions, path+".extensions")
	v.validateEntryUniqueness(c.Entries, path)

	for i := range c.Entries {
		v.validateEntry(&c.Entries[i], fmt.Sprintf("%s.entries[%d]", path, i), depth)
	}
}

func (v *validator) validateHost(host *catalog.HostInfo, path string) {
	if host != nil && host.DisplayName == "" {
		v.addError(CodeHostMember, path+".displayName", "host.displayName is required and must not be empty")
	}
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
			v.addError(CodeEntryDuplicate, entryPath, fmt.Sprintf(
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
		v.addError(CodeEntryVersion, path+".identifier", fmt.Sprintf(
			"identifier %q cannot appear with and without version", entry.Identifier))
	}

	if seenVersioned[idVersion{entry.Identifier, entry.Version}] {
		v.addError(CodeEntryDuplicate, path, fmt.Sprintf(
			"duplicate (identifier, version) pair: (%q, %q)", entry.Identifier, entry.Version))
	}
}

func (v *validator) validateEntry(entry *catalog.CatalogEntry, path string, depth int) {
	v.validateRequiredEntryFields(entry, path)
	v.validateArtifactSource(entry, path)
	v.validateTimestamp(entry.UpdatedAt, path+".updatedAt")
	v.validateExtensionKeys(entry.Extensions, path+".extensions")
	v.validatePublisher(entry.Publisher, path+".publisher")
	v.validateEntryTrust(entry, path, depth)
	v.validateNestedCatalog(entry, path, depth)

	if entry.Identifier != "" && !strings.Contains(entry.Identifier, ":") {
		v.addWarning(CodeIdentifierNotURI, path+".identifier", "identifier SHOULD be a URN or URI")
	}
}

func (v *validator) validateRequiredEntryFields(entry *catalog.CatalogEntry, path string) {
	if entry.Identifier == "" {
		v.addError(CodeEntryMember, path+".identifier", "identifier is required and must not be empty")
	}

	if entry.Type == "" {
		v.addError(CodeEntryMember, path+".type", "type is required and must not be empty")
	}
}

func (v *validator) validatePublisher(publisher *catalog.Publisher, path string) {
	if publisher == nil {
		return
	}

	if publisher.Identifier == "" {
		v.addError(CodePublisherMember, path+".identifier", "publisher.identifier is required and must not be empty")
	}

	if publisher.DisplayName == "" {
		v.addError(CodePublisherMember, path+".displayName", "publisher.displayName is required and must not be empty")
	}
}

func (v *validator) validateArtifactSource(entry *catalog.CatalogEntry, path string) {
	hasURL := entry.URL != ""
	hasData := len(entry.Data) > 0

	switch {
	case hasURL && hasData:
		v.addError(CodeEntryArtifact, path, "entry must have exactly one of 'url' or 'data', found both")
	case !hasURL && !hasData:
		v.addError(CodeEntryArtifact, path, "entry must have exactly one of 'url' or 'data'")
	}
}

// validateTimestamp checks an optional RFC 3339 timestamp.
func (v *validator) validateTimestamp(value, path string) {
	if value == "" {
		return
	}

	if _, err := time.Parse(time.RFC3339, value); err != nil {
		name := path[strings.LastIndexByte(path, '.')+1:]
		v.addError(CodeTimestamp, path, fmt.Sprintf("%s is not a valid RFC 3339 datetime: %q", name, value))
	}
}

func (v *validator) validateNestedCatalog(entry *catalog.CatalogEntry, path string, depth int) {
	if !entry.IsNestedCatalog() {
		return
	}

	if depth >= v.cfg.maxDepth {
		v.addError(CodeNestedDepth, path, fmt.Sprintf(
			"nested catalog depth exceeds recommended limit of %d", v.cfg.maxDepth))

		return
	}

	if len(entry.Data) == 0 {
		return
	}

	nested, err := catalog.Parse(entry.Data)
	if err != nil {
		v.addError(CodeNestedInvalid, path+".data", fmt.Sprintf(
			"nested catalog data is not a valid AI Catalog: %v", err))

		return
	}

	v.validateCatalog(nested, path+".data", depth+1)
}

// reverseDNSKey matches a reverse-DNS extension key such as
// "com.example.confidenceScore".
var reverseDNSKey = regexp.MustCompile(
	`^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$`)

// validateExtensionKeys requires every key to be a URL or a reverse-DNS string.
func (v *validator) validateExtensionKeys(extensions map[string]json.RawMessage, path string) {
	for _, key := range slices.Sorted(maps.Keys(extensions)) {
		if !isExtensionKey(key) {
			v.addError(CodeExtensionKey, path, fmt.Sprintf(
				"extension key %q must be a valid URL or a reverse-DNS string", key))
		}
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
		v.addError(CodeSpecVersion, path, "specVersion must not be empty")

		return
	}

	parts := strings.Split(specVersion, ".")
	if len(parts) != specVersionParts {
		v.addError(CodeSpecVersion, path, fmt.Sprintf(
			"specVersion must be in Major.Minor format (e.g., '1.0'), found %q", specVersion))

		return
	}

	major, majorErr := strconv.Atoi(parts[0])
	_, minorErr := strconv.Atoi(parts[1])

	if majorErr != nil || minorErr != nil || major < 0 {
		v.addError(CodeSpecVersion, path, fmt.Sprintf(
			"specVersion major and minor components must be non-negative integers, found %q",
			specVersion))

		return
	}

	if major > maxSupportedMajor {
		v.addError(CodeSpecVersion, path, fmt.Sprintf(
			"unsupported specVersion major version: %d (this implementation supports major version %d)",
			major, maxSupportedMajor))
	}
}
