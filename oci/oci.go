// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

// Package oci packs and unpacks AI Catalog documents as OCI artifact sets and
// standard OCI image layouts, including cosign verification referrers. It uses
// only the standard library; distribution (oras) and signing (cosign) are the
// caller's responsibility.
package oci

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/agntcy/ai-catalog-go-sdk/catalog"
)

// OCI and AI Catalog media types and annotation keys used by the artifact set.
const (
	OCIImageIndexMediaType    = "application/vnd.oci.image.index.v1+json"
	OCIImageManifestMediaType = "application/vnd.oci.image.manifest.v1+json"
	AICatalogMediaType        = "application/ai-catalog+json"
	EntryConfigMediaType      = "application/vnd.ai-catalog.entry.config.v1+json"
	OCILayoutVersion          = "1.0.0"
	OCIRefNameAnnotation      = "org.opencontainers.image.ref.name"

	TrustManifestArtifactType     = "application/vnd.ai-catalog.trust-manifest.v1+json"
	TrustManifestConfigMediaType  = "application/vnd.ai-catalog.trust-manifest.config.v1+json"
	CosignSignatureArtifactType   = "application/vnd.ai-catalog.cosign.signature.v1"
	CosignSignatureConfigMedia    = "application/vnd.ai-catalog.cosign.signature.config.v1+json"
	CosignSignatureLayerMediaType = "application/vnd.dev.sigstore.cosign.signature"
	CosignPublicKeyArtifactType   = "application/vnd.ai-catalog.cosign.public-key.v1"
	CosignPublicKeyConfigMedia    = "application/vnd.ai-catalog.cosign.public-key.config.v1+json"
	CosignPublicKeyLayerMediaType = "application/vnd.dev.sigstore.cosign.public-key"
)

// ociSchemaVersion is the OCI image spec schemaVersion value.
const ociSchemaVersion = 2

// Annotation keys used to round-trip catalog-level and entry-level fields.
const (
	annotationSpecVersion = "ai-catalog.specVersion"
	annotationHost        = "ai-catalog.host"
	annotationMetadata    = "ai-catalog.metadata"
	annotationIdentifier  = "ai-catalog.identifier"
	annotationDisplayName = "ai-catalog.displayName"
	annotationVersion     = "ai-catalog.version"
	annotationIdentity    = "ai-catalog.identity"
)

// Errors returned by this package. Callers may test for these with errors.Is.
var (
	ErrInvalidEntryContent      = errors.New("catalog entry must contain exactly one of url or data before packing to OCI")
	ErrMissingManifest          = errors.New("missing manifest for digest")
	ErrMissingBlob              = errors.New("missing blob for digest")
	ErrUnsupportedIndexArtifact = fmt.Errorf("OCI index artifactType must be %q", AICatalogMediaType)
	ErrMissingSpecVersion       = errors.New("OCI index is missing ai-catalog.specVersion annotation")
	ErrMissingEntryContent      = errors.New("entry is missing both OCI layer content and external url")
	ErrInvalidLayoutTag         = errors.New("OCI layout tag must not be empty")
	ErrNonEmptyLayoutDirectory  = errors.New("OCI layout output directory must be empty or not exist")
	ErrInvalidDigest            = errors.New("invalid OCI digest")
	ErrUnsupportedLayoutVersion = fmt.Errorf("OCI layout version must be %q", OCILayoutVersion)
	ErrMissingLayoutReference   = errors.New("OCI layout is missing ai-catalog root reference")
	ErrAmbiguousLayoutReference = errors.New("OCI layout contains multiple ai-catalog root references; pass an explicit ref name")
	ErrMissingSubjectDescriptor = errors.New("missing OCI subject descriptor for digest")
)

// OCIDescriptor references content by digest, following the OCI content
// descriptor schema.
type OCIDescriptor struct {
	MediaType    string            `json:"mediaType"`
	Digest       string            `json:"digest"`
	Size         uint64            `json:"size"`
	ArtifactType string            `json:"artifactType,omitempty"`
	Annotations  map[string]string `json:"annotations,omitempty"`
}

// OCIImageIndex is an OCI image index (a list of manifest descriptors).
type OCIImageIndex struct {
	SchemaVersion uint32            `json:"schemaVersion"`
	MediaType     string            `json:"mediaType"`
	ArtifactType  string            `json:"artifactType,omitempty"`
	Manifests     []OCIDescriptor   `json:"manifests"`
	Annotations   map[string]string `json:"annotations,omitempty"`
}

// OCIImageManifest is an OCI image manifest describing a single artifact.
type OCIImageManifest struct {
	SchemaVersion uint32            `json:"schemaVersion"`
	MediaType     string            `json:"mediaType"`
	ArtifactType  string            `json:"artifactType,omitempty"`
	Config        OCIDescriptor     `json:"config"`
	Layers        []OCIDescriptor   `json:"layers,omitempty"`
	Subject       *OCIDescriptor    `json:"subject,omitempty"`
	Annotations   map[string]string `json:"annotations,omitempty"`
}

// ArtifactSet is the in-memory OCI representation of an AI Catalog: an image
// index, the entry manifests keyed by digest, referrer manifests keyed by
// subject digest, and the content blobs keyed by digest.
type ArtifactSet struct {
	Index     OCIImageIndex                 `json:"index"`
	Manifests map[string]OCIImageManifest   `json:"manifests,omitempty"`
	Referrers map[string][]OCIImageManifest `json:"referrers,omitempty"`
	Blobs     map[string][]byte             `json:"blobs,omitempty"`
}

// ociLayoutMetadata is the content of the oci-layout marker file.
type ociLayoutMetadata struct {
	ImageLayoutVersion string `json:"imageLayoutVersion"`
}

// entryConfig is the OCI config blob carrying an entry's descriptive fields.
type entryConfig struct {
	Identifier  string                     `json:"identifier"`
	DisplayName string                     `json:"displayName,omitempty"`
	Description string                     `json:"description,omitempty"`
	Tags        []string                   `json:"tags,omitempty"`
	Version     string                     `json:"version,omitempty"`
	UpdatedAt   string                     `json:"updatedAt,omitempty"`
	Metadata    map[string]json.RawMessage `json:"metadata,omitempty"`
	Publisher   *catalog.Publisher         `json:"publisher,omitempty"`
	URL         string                     `json:"url,omitempty"`
}

// cosignSignatureConfig is the config blob for a cosign signature referrer.
type cosignSignatureConfig struct {
	Identity         string `json:"identity"`
	PayloadDigest    string `json:"payloadDigest"`
	PayloadMediaType string `json:"payloadMediaType"`
}

// cosignPublicKeyConfig is the config blob for a cosign public-key referrer.
type cosignPublicKeyConfig struct {
	Identity      string `json:"identity"`
	PayloadDigest string `json:"payloadDigest"`
	Format        string `json:"format"`
}

func entryConfigFromEntry(entry *catalog.CatalogEntry) entryConfig {
	return entryConfig{
		Identifier:  entry.Identifier,
		DisplayName: entry.DisplayName,
		Description: entry.Description,
		Tags:        entry.Tags,
		Version:     entry.Version,
		UpdatedAt:   entry.UpdatedAt,
		Metadata:    entry.Metadata,
		Publisher:   entry.Publisher,
		URL:         entry.URL,
	}
}

// descriptorForBytes builds an OCI descriptor for bytes with a SHA-256 digest.
func descriptorForBytes(data []byte, mediaType, artifactType string, annotations map[string]string) OCIDescriptor {
	sum := sha256.Sum256(data)

	return OCIDescriptor{
		MediaType:    mediaType,
		Digest:       "sha256:" + hex.EncodeToString(sum[:]),
		Size:         uint64(len(data)),
		ArtifactType: artifactType,
		Annotations:  annotations,
	}
}

// storeBlob records bytes in blobs keyed by digest and returns its descriptor.
func storeBlob(blobs map[string][]byte, data []byte, mediaType string) OCIDescriptor {
	descriptor := descriptorForBytes(data, mediaType, "", nil)
	blobs[descriptor.Digest] = append([]byte(nil), data...)

	return descriptor
}

func entryAnnotations(entry *catalog.CatalogEntry) map[string]string {
	annotations := map[string]string{annotationIdentifier: entry.Identifier}

	if entry.DisplayName != "" {
		annotations[annotationDisplayName] = entry.DisplayName
	}

	if entry.Version != "" {
		annotations[annotationVersion] = entry.Version
	}

	return annotations
}

func trustManifestAnnotations(manifest *catalog.TrustManifest) map[string]string {
	return map[string]string{annotationIdentity: manifest.Identity}
}

func cosignSignatureAnnotations(identity, payloadDigest string) map[string]string {
	return map[string]string{
		annotationIdentity:                identity,
		"ai-catalog.payloadDigest":        payloadDigest,
		"ai-catalog.payloadMediaType":     TrustManifestArtifactType,
		"ai-catalog.verificationMaterial": "cosign-signature",
	}
}

func cosignPublicKeyAnnotations(identity, payloadDigest string) map[string]string {
	return map[string]string{
		annotationIdentity:                identity,
		"ai-catalog.payloadDigest":        payloadDigest,
		"ai-catalog.payloadMediaType":     TrustManifestArtifactType,
		"ai-catalog.verificationMaterial": "cosign-public-key",
	}
}

// sortedKeys returns m's keys sorted, for deterministic output.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}

	sort.Strings(keys)

	return keys
}
