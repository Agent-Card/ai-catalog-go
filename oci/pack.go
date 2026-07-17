// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package oci

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/agntcy/ai-catalog-go-sdk/catalog"
)

// errValueAbsent is a sentinel distinguishing an absent optional value from a
// parse error; callers test for it with errors.Is.
var errValueAbsent = errors.New("optional value absent")

// PackCatalog converts an AI Catalog document into an OCI artifact set. Each
// entry becomes an OCI image manifest; an entry trust manifest becomes a
// referrer manifest attached to the entry's manifest.
func PackCatalog(c *catalog.AICatalog) (*ArtifactSet, error) {
	set := &ArtifactSet{
		Manifests: make(map[string]OCIImageManifest),
		Referrers: make(map[string][]OCIImageManifest),
		Blobs:     make(map[string][]byte),
	}

	indexDescriptors := make([]OCIDescriptor, 0, len(c.Entries))

	for i := range c.Entries {
		entry := &c.Entries[i]

		manifestDescriptor, err := set.packEntry(entry)
		if err != nil {
			return nil, err
		}

		indexDescriptors = append(indexDescriptors, manifestDescriptor)
	}

	annotations, err := catalogAnnotations(c)
	if err != nil {
		return nil, err
	}

	set.Index = OCIImageIndex{
		SchemaVersion: ociSchemaVersion,
		MediaType:     OCIImageIndexMediaType,
		ArtifactType:  AICatalogMediaType,
		Manifests:     indexDescriptors,
		Annotations:   annotations,
	}

	return set, nil
}

func (set *ArtifactSet) packEntry(entry *catalog.CatalogEntry) (OCIDescriptor, error) {
	configBytes, err := json.Marshal(entryConfigFromEntry(entry))
	if err != nil {
		return OCIDescriptor{}, fmt.Errorf("marshal entry config: %w", err)
	}

	configDescriptor := storeBlob(set.Blobs, configBytes, EntryConfigMediaType)

	layers, err := set.packEntryLayers(entry)
	if err != nil {
		return OCIDescriptor{}, err
	}

	annotations := entryAnnotations(entry)
	manifest := OCIImageManifest{
		SchemaVersion: ociSchemaVersion,
		MediaType:     OCIImageManifestMediaType,
		ArtifactType:  entry.Type,
		Config:        configDescriptor,
		Layers:        layers,
		Annotations:   annotations,
	}

	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		return OCIDescriptor{}, fmt.Errorf("marshal entry manifest: %w", err)
	}

	manifestDescriptor := descriptorForBytes(manifestBytes, OCIImageManifestMediaType, entry.Type, annotations)

	if err := set.packEntryTrustReferrer(entry, manifestDescriptor); err != nil {
		return OCIDescriptor{}, err
	}

	set.Manifests[manifestDescriptor.Digest] = manifest

	return manifestDescriptor, nil
}

func (set *ArtifactSet) packEntryLayers(entry *catalog.CatalogEntry) ([]OCIDescriptor, error) {
	hasURL := entry.URL != ""
	hasData := len(entry.Data) > 0

	switch {
	case hasURL && !hasData:
		return nil, nil
	case !hasURL && hasData:
		layer := storeBlob(set.Blobs, entry.Data, entry.Type)

		return []OCIDescriptor{layer}, nil
	default:
		return nil, fmt.Errorf("%w: %q", ErrInvalidEntryContent, entry.Identifier)
	}
}

func (set *ArtifactSet) packEntryTrustReferrer(entry *catalog.CatalogEntry, subject OCIDescriptor) error {
	if entry.TrustManifest == nil {
		return nil
	}

	trustBytes, err := json.Marshal(entry.TrustManifest)
	if err != nil {
		return fmt.Errorf("marshal trust manifest: %w", err)
	}

	trustConfig := storeBlob(set.Blobs, trustBytes, TrustManifestConfigMediaType)
	referrer := OCIImageManifest{
		SchemaVersion: ociSchemaVersion,
		MediaType:     OCIImageManifestMediaType,
		ArtifactType:  TrustManifestArtifactType,
		Config:        trustConfig,
		Subject:       &subject,
		Annotations:   trustManifestAnnotations(entry.TrustManifest),
	}

	set.Referrers[subject.Digest] = append(set.Referrers[subject.Digest], referrer)

	return nil
}

// UnpackCatalog reconstructs an AI Catalog document from an OCI artifact set.
func UnpackCatalog(set *ArtifactSet) (*catalog.AICatalog, error) {
	if set.Index.ArtifactType != AICatalogMediaType {
		return nil, ErrUnsupportedIndexArtifact
	}

	specVersion, ok := set.Index.Annotations[annotationSpecVersion]
	if !ok {
		return nil, ErrMissingSpecVersion
	}

	host, err := hostFromAnnotations(set.Index.Annotations)
	if err != nil && !errors.Is(err, errValueAbsent) {
		return nil, err
	}

	metadata, err := metadataFromAnnotations(set.Index.Annotations)
	if err != nil && !errors.Is(err, errValueAbsent) {
		return nil, err
	}

	entries := make([]catalog.CatalogEntry, 0, len(set.Index.Manifests))

	for i := range set.Index.Manifests {
		entry, err := set.unpackEntry(&set.Index.Manifests[i])
		if err != nil {
			return nil, err
		}

		entries = append(entries, entry)
	}

	return &catalog.AICatalog{
		SpecVersion: specVersion,
		Host:        host,
		Entries:     entries,
		Metadata:    metadata,
	}, nil
}

func (set *ArtifactSet) unpackEntry(descriptor *OCIDescriptor) (catalog.CatalogEntry, error) {
	manifest, ok := set.Manifests[descriptor.Digest]
	if !ok {
		return catalog.CatalogEntry{}, fmt.Errorf("%w: %q", ErrMissingManifest, descriptor.Digest)
	}

	configBytes, ok := set.Blobs[manifest.Config.Digest]
	if !ok {
		return catalog.CatalogEntry{}, fmt.Errorf("%w: %q", ErrMissingBlob, manifest.Config.Digest)
	}

	var config entryConfig
	if err := json.Unmarshal(configBytes, &config); err != nil {
		return catalog.CatalogEntry{}, fmt.Errorf("parse entry config: %w", err)
	}

	url, data, err := set.unpackEntryContent(&config, &manifest)
	if err != nil {
		return catalog.CatalogEntry{}, err
	}

	trustManifest, err := set.unpackEntryTrust(descriptor.Digest)
	if err != nil && !errors.Is(err, errValueAbsent) {
		return catalog.CatalogEntry{}, err
	}

	return catalog.CatalogEntry{
		Identifier:    config.Identifier,
		DisplayName:   config.DisplayName,
		Type:          entryType(descriptor, &manifest),
		URL:           url,
		Data:          data,
		Version:       config.Version,
		Description:   config.Description,
		Tags:          config.Tags,
		Publisher:     config.Publisher,
		TrustManifest: trustManifest,
		UpdatedAt:     config.UpdatedAt,
		Metadata:      config.Metadata,
	}, nil
}

func (set *ArtifactSet) unpackEntryContent(config *entryConfig, manifest *OCIImageManifest) (string, json.RawMessage, error) {
	if config.URL != "" {
		return config.URL, nil, nil
	}

	if len(manifest.Layers) > 0 {
		layerDigest := manifest.Layers[0].Digest

		layerBytes, ok := set.Blobs[layerDigest]
		if !ok {
			return "", nil, fmt.Errorf("%w: %q", ErrMissingBlob, layerDigest)
		}

		return "", json.RawMessage(append([]byte(nil), layerBytes...)), nil
	}

	return "", nil, fmt.Errorf("%w: %q", ErrMissingEntryContent, config.Identifier)
}

func (set *ArtifactSet) unpackEntryTrust(subjectDigest string) (*catalog.TrustManifest, error) {
	for i := range set.Referrers[subjectDigest] {
		referrer := &set.Referrers[subjectDigest][i]
		if referrer.ArtifactType != TrustManifestArtifactType {
			continue
		}

		bytes, ok := set.Blobs[referrer.Config.Digest]
		if !ok {
			return nil, fmt.Errorf("%w: %q", ErrMissingBlob, referrer.Config.Digest)
		}

		var manifest catalog.TrustManifest
		if err := json.Unmarshal(bytes, &manifest); err != nil {
			return nil, fmt.Errorf("parse trust manifest: %w", err)
		}

		return &manifest, nil
	}

	return nil, errValueAbsent
}

func entryType(descriptor *OCIDescriptor, manifest *OCIImageManifest) string {
	if descriptor.ArtifactType != "" {
		return descriptor.ArtifactType
	}

	return manifest.ArtifactType
}

func catalogAnnotations(c *catalog.AICatalog) (map[string]string, error) {
	annotations := map[string]string{annotationSpecVersion: c.SpecVersion}

	if c.Host != nil {
		hostJSON, err := json.Marshal(c.Host)
		if err != nil {
			return nil, fmt.Errorf("marshal host: %w", err)
		}

		annotations[annotationHost] = string(hostJSON)
	}

	if len(c.Metadata) > 0 {
		metadataJSON, err := json.Marshal(c.Metadata)
		if err != nil {
			return nil, fmt.Errorf("marshal metadata: %w", err)
		}

		annotations[annotationMetadata] = string(metadataJSON)
	}

	return annotations, nil
}

func hostFromAnnotations(annotations map[string]string) (*catalog.HostInfo, error) {
	raw, ok := annotations[annotationHost]
	if !ok {
		return nil, errValueAbsent
	}

	var host catalog.HostInfo
	if err := json.Unmarshal([]byte(raw), &host); err != nil {
		return nil, fmt.Errorf("parse host annotation: %w", err)
	}

	return &host, nil
}

func metadataFromAnnotations(annotations map[string]string) (map[string]json.RawMessage, error) {
	raw, ok := annotations[annotationMetadata]
	if !ok {
		return nil, errValueAbsent
	}

	var metadata map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &metadata); err != nil {
		return nil, fmt.Errorf("parse metadata annotation: %w", err)
	}

	return metadata, nil
}
