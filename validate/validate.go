// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

// Package validate provides semantic validation and conformance-level
// detection for AI Catalog documents, mirroring the AI Catalog specification's
// Minimal / Discoverable / Trusted conformance levels.
package validate

import (
	"encoding/json"
	"fmt"
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

	// Trusted requires a valid Discoverable document plus a trust manifest on
	// the host or on at least one entry.
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
	v.validateCatalog(c, "catalog", 1)

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

	if c.Host.TrustManifest != nil || anyEntryHasTrustManifest(c.Entries) {
		return Trusted
	}

	return Discoverable
}

func anyEntryHasTrustManifest(entries []catalog.CatalogEntry) bool {
	for i := range entries {
		if entries[i].TrustManifest != nil {
			return true
		}
	}

	return false
}

func (v *validator) validateCatalog(c *catalog.AICatalog, path string, depth int) {
	v.validateSpecVersion(c.SpecVersion, path+".specVersion")
	v.validateHost(c.Host, path+".host")
	v.validateMetadataKeys(c.Metadata, path+".metadata")
	v.validateEntryUniqueness(c.Entries, path)

	for i := range c.Entries {
		v.validateEntry(&c.Entries[i], fmt.Sprintf("%s.entries[%d]", path, i), depth)
	}
}

// validateHost enforces the required Host Info members: displayName, and
// trustManifest.identity when a host trust manifest is present.
func (v *validator) validateHost(host *catalog.HostInfo, path string) {
	if host == nil {
		return
	}

	if host.DisplayName == "" {
		v.addError(path+".displayName", "host.displayName is required and must not be empty")
	}

	if host.TrustManifest != nil {
		v.validateMetadataKeys(host.TrustManifest.Metadata, path+".trustManifest.metadata")

		if host.TrustManifest.Identity == "" {
			v.addError(path+".trustManifest.identity",
				"trustManifest.identity is required and must not be empty")
		}
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
	v.validateMetadataKeys(entry.Metadata, path+".metadata")
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

func (v *validator) validateEntryTrust(entry *catalog.CatalogEntry, path string) {
	manifest := entry.TrustManifest
	if manifest == nil {
		return
	}

	v.validateMetadataKeys(manifest.Metadata, path+".trustManifest.metadata")

	if manifest.Identity == "" {
		v.addError(path+".trustManifest.identity",
			"trustManifest.identity is required and must not be empty")

		return
	}

	// Identity binds to the entry by domain alignment, not exact equality.
	if aligned, applies := catalog.IdentityBindsToEntry(
		entry.Identifier, manifest.Identity); applies && !aligned {
		publisherDomain, _ := catalog.PublisherDomain(entry.Identifier)

		if identityDomain, ok := catalog.IdentityDomain(manifest.Identity); ok {
			v.addError(path+".trustManifest.identity", fmt.Sprintf(
				"trustManifest.identity domain %q does not align with the entry identifier publisher domain %q",
				identityDomain, publisherDomain))
		} else {
			v.addError(path+".trustManifest.identity", fmt.Sprintf(
				"trustManifest.identity %q has no trust domain to align with the entry identifier publisher domain %q",
				manifest.Identity, publisherDomain))
		}
	}
}

func (v *validator) validateNestedCatalog(entry *catalog.CatalogEntry, path string, depth int) {
	if entry.Type != catalog.MediaTypeCatalog {
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

func (v *validator) validateMetadataKeys(metadata map[string]json.RawMessage, path string) {
	for key := range metadata {
		if key == "" {
			v.addError(path, "metadata keys must be non-empty strings")
		}
	}
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
