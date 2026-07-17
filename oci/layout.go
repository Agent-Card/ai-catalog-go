// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package oci

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// File modes for OCI layout output.
const (
	layoutFileMode = 0o600
	layoutDirMode  = 0o750
)

// AttachCosignVerificationArtifacts attaches a detached cosign signature and
// its public key as OCI referrers to the entry manifest identified by
// subjectDigest.
func (set *ArtifactSet) AttachCosignVerificationArtifacts(
	subjectDigest, identity, payloadDigest string,
	signature, publicKey []byte,
) error {
	subject, ok := set.findIndexDescriptor(subjectDigest)
	if !ok {
		return fmt.Errorf("%w: %q", ErrMissingSubjectDescriptor, subjectDigest)
	}

	signatureManifest, err := set.buildCosignReferrer(
		cosignReferrerParams{
			artifactType:    CosignSignatureArtifactType,
			configMediaType: CosignSignatureConfigMedia,
			config: cosignSignatureConfig{
				Identity:         identity,
				PayloadDigest:    payloadDigest,
				PayloadMediaType: TrustManifestArtifactType,
			},
			layerMediaType: CosignSignatureLayerMediaType,
			layer:          signature,
			annotations:    cosignSignatureAnnotations(identity, payloadDigest),
			subject:        subject,
		})
	if err != nil {
		return err
	}

	publicKeyManifest, err := set.buildCosignReferrer(
		cosignReferrerParams{
			artifactType:    CosignPublicKeyArtifactType,
			configMediaType: CosignPublicKeyConfigMedia,
			config: cosignPublicKeyConfig{
				Identity:      identity,
				PayloadDigest: payloadDigest,
				Format:        "pem",
			},
			layerMediaType: CosignPublicKeyLayerMediaType,
			layer:          publicKey,
			annotations:    cosignPublicKeyAnnotations(identity, payloadDigest),
			subject:        subject,
		})
	if err != nil {
		return err
	}

	set.Referrers[subjectDigest] = append(set.Referrers[subjectDigest], signatureManifest, publicKeyManifest)

	return nil
}

type cosignReferrerParams struct {
	artifactType    string
	configMediaType string
	config          any
	layerMediaType  string
	layer           []byte
	annotations     map[string]string
	subject         OCIDescriptor
}

func (set *ArtifactSet) buildCosignReferrer(params cosignReferrerParams) (OCIImageManifest, error) {
	configBytes, err := json.Marshal(params.config)
	if err != nil {
		return OCIImageManifest{}, fmt.Errorf("marshal cosign referrer config: %w", err)
	}

	configDescriptor := storeBlob(set.Blobs, configBytes, params.configMediaType)
	layerDescriptor := storeBlob(set.Blobs, params.layer, params.layerMediaType)
	subject := params.subject

	return OCIImageManifest{
		SchemaVersion: ociSchemaVersion,
		MediaType:     OCIImageManifestMediaType,
		ArtifactType:  params.artifactType,
		Config:        configDescriptor,
		Layers:        []OCIDescriptor{layerDescriptor},
		Subject:       &subject,
		Annotations:   params.annotations,
	}, nil
}

func (set *ArtifactSet) findIndexDescriptor(digest string) (OCIDescriptor, bool) {
	for _, descriptor := range set.Index.Manifests {
		if descriptor.Digest == digest {
			return descriptor, true
		}
	}

	return OCIDescriptor{}, false
}

// ExportLayout writes the artifact set to layoutDir as a standard OCI image
// layout, tagging the root index with tag.
func (set *ArtifactSet) ExportLayout(layoutDir, tag string) error {
	if strings.TrimSpace(tag) == "" {
		return ErrInvalidLayoutTag
	}

	if err := prepareLayoutDirectory(layoutDir); err != nil {
		return err
	}

	rootIndexBytes, err := json.Marshal(set.Index)
	if err != nil {
		return fmt.Errorf("marshal root index: %w", err)
	}

	rootDescriptor := descriptorForBytes(
		rootIndexBytes, OCIImageIndexMediaType, set.Index.ArtifactType,
		map[string]string{OCIRefNameAnnotation: tag})

	layoutDescriptors := make([]OCIDescriptor, 0, 1+len(set.Index.Manifests))
	layoutDescriptors = append(layoutDescriptors, rootDescriptor)
	layoutDescriptors = append(layoutDescriptors, set.Index.Manifests...)

	if err := writeLayoutBlob(layoutDir, rootDescriptor.Digest, rootIndexBytes); err != nil {
		return err
	}

	if err := set.writeManifestBlobs(layoutDir); err != nil {
		return err
	}

	referrerDescriptors, err := set.writeReferrerBlobs(layoutDir)
	if err != nil {
		return err
	}

	layoutDescriptors = append(layoutDescriptors, referrerDescriptors...)

	if err := set.writeContentBlobs(layoutDir); err != nil {
		return err
	}

	return writeLayoutIndexFiles(layoutDir, layoutDescriptors)
}

func (set *ArtifactSet) writeManifestBlobs(layoutDir string) error {
	for _, digest := range sortedKeys(set.Manifests) {
		manifest := set.Manifests[digest]

		manifestBytes, err := json.Marshal(manifest)
		if err != nil {
			return fmt.Errorf("marshal manifest: %w", err)
		}

		if err := writeLayoutBlob(layoutDir, digest, manifestBytes); err != nil {
			return err
		}
	}

	return nil
}

func (set *ArtifactSet) writeReferrerBlobs(layoutDir string) ([]OCIDescriptor, error) {
	var descriptors []OCIDescriptor

	for _, subjectDigest := range sortedKeys(set.Referrers) {
		for i := range set.Referrers[subjectDigest] {
			manifest := set.Referrers[subjectDigest][i]

			manifestBytes, err := json.Marshal(manifest)
			if err != nil {
				return nil, fmt.Errorf("marshal referrer manifest: %w", err)
			}

			descriptor := descriptorForBytes(
				manifestBytes, OCIImageManifestMediaType, manifest.ArtifactType, manifest.Annotations)
			descriptors = append(descriptors, descriptor)

			if err := writeLayoutBlob(layoutDir, descriptor.Digest, manifestBytes); err != nil {
				return nil, err
			}
		}
	}

	return descriptors, nil
}

func (set *ArtifactSet) writeContentBlobs(layoutDir string) error {
	for _, digest := range sortedKeys(set.Blobs) {
		if err := writeLayoutBlob(layoutDir, digest, set.Blobs[digest]); err != nil {
			return err
		}
	}

	return nil
}

func writeLayoutIndexFiles(layoutDir string, descriptors []OCIDescriptor) error {
	layoutIndex := OCIImageIndex{
		SchemaVersion: ociSchemaVersion,
		MediaType:     OCIImageIndexMediaType,
		Manifests:     descriptors,
	}

	indexBytes, err := json.MarshalIndent(layoutIndex, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal layout index: %w", err)
	}

	metadataBytes, err := json.MarshalIndent(ociLayoutMetadata{ImageLayoutVersion: OCILayoutVersion}, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal layout metadata: %w", err)
	}

	if err := os.WriteFile(filepath.Join(layoutDir, "index.json"), indexBytes, layoutFileMode); err != nil {
		return fmt.Errorf("write index.json: %w", err)
	}

	if err := os.WriteFile(filepath.Join(layoutDir, "oci-layout"), metadataBytes, layoutFileMode); err != nil {
		return fmt.Errorf("write oci-layout: %w", err)
	}

	return nil
}

// ImportLayout reads a standard OCI image layout from layoutDir back into an
// artifact set. When refName is empty the single ai-catalog root reference is
// used; if multiple exist, refName is required.
func ImportLayout(layoutDir, refName string) (*ArtifactSet, error) {
	if err := checkLayoutVersion(layoutDir); err != nil {
		return nil, err
	}

	var layoutIndex OCIImageIndex
	if err := readLayoutFile(filepath.Join(layoutDir, "index.json"), &layoutIndex); err != nil {
		return nil, err
	}

	rootDescriptor, err := selectLayoutRootDescriptor(&layoutIndex, refName)
	if err != nil {
		return nil, err
	}

	var rootIndex OCIImageIndex
	if err := readLayoutJSONBlob(layoutDir, rootDescriptor.Digest, &rootIndex); err != nil {
		return nil, err
	}

	set := &ArtifactSet{
		Index:     rootIndex,
		Manifests: make(map[string]OCIImageManifest),
		Referrers: make(map[string][]OCIImageManifest),
		Blobs:     make(map[string][]byte),
	}

	entryDigests := make(map[string]bool, len(rootIndex.Manifests))
	for _, descriptor := range rootIndex.Manifests {
		entryDigests[descriptor.Digest] = true
	}

	if err := set.importEntryManifests(layoutDir); err != nil {
		return nil, err
	}

	if err := set.importReferrers(layoutDir, &layoutIndex, rootDescriptor.Digest, entryDigests); err != nil {
		return nil, err
	}

	return set, nil
}

func (set *ArtifactSet) importEntryManifests(layoutDir string) error {
	for i := range set.Index.Manifests {
		descriptor := set.Index.Manifests[i]

		var manifest OCIImageManifest
		if err := readLayoutJSONBlob(layoutDir, descriptor.Digest, &manifest); err != nil {
			return err
		}

		if err := loadManifestBlobs(layoutDir, &manifest, set.Blobs); err != nil {
			return err
		}

		set.Manifests[descriptor.Digest] = manifest
	}

	return nil
}

func (set *ArtifactSet) importReferrers(
	layoutDir string, layoutIndex *OCIImageIndex, rootDigest string, entryDigests map[string]bool,
) error {
	for i := range layoutIndex.Manifests {
		descriptor := layoutIndex.Manifests[i]

		if descriptor.Digest == rootDigest || entryDigests[descriptor.Digest] {
			continue
		}

		if descriptor.MediaType != OCIImageManifestMediaType {
			continue
		}

		var manifest OCIImageManifest
		if err := readLayoutJSONBlob(layoutDir, descriptor.Digest, &manifest); err != nil {
			return err
		}

		if manifest.Subject == nil || !entryDigests[manifest.Subject.Digest] {
			continue
		}

		if err := loadManifestBlobs(layoutDir, &manifest, set.Blobs); err != nil {
			return err
		}

		set.Referrers[manifest.Subject.Digest] = append(set.Referrers[manifest.Subject.Digest], manifest)
	}

	return nil
}

func selectLayoutRootDescriptor(layoutIndex *OCIImageIndex, refName string) (*OCIDescriptor, error) {
	var roots []*OCIDescriptor

	for i := range layoutIndex.Manifests {
		descriptor := &layoutIndex.Manifests[i]
		if descriptor.MediaType == OCIImageIndexMediaType && descriptor.ArtifactType == AICatalogMediaType {
			roots = append(roots, descriptor)
		}
	}

	if refName != "" {
		for _, descriptor := range roots {
			if descriptor.Annotations[OCIRefNameAnnotation] == refName {
				return descriptor, nil
			}
		}

		return nil, fmt.Errorf("%w: %q", ErrMissingLayoutReference, refName)
	}

	switch len(roots) {
	case 1:
		return roots[0], nil
	case 0:
		return nil, fmt.Errorf("%w: %q", ErrMissingLayoutReference, "latest")
	default:
		return nil, ErrAmbiguousLayoutReference
	}
}

func checkLayoutVersion(layoutDir string) error {
	var metadata ociLayoutMetadata
	if err := readLayoutFile(filepath.Join(layoutDir, "oci-layout"), &metadata); err != nil {
		return err
	}

	if metadata.ImageLayoutVersion != OCILayoutVersion {
		return fmt.Errorf("%w, found %q", ErrUnsupportedLayoutVersion, metadata.ImageLayoutVersion)
	}

	return nil
}

func prepareLayoutDirectory(layoutDir string) error {
	info, err := os.Stat(layoutDir)

	switch {
	case err == nil && info.IsDir():
		empty, emptyErr := isDirEmpty(layoutDir)
		if emptyErr != nil {
			return emptyErr
		}

		if !empty {
			return fmt.Errorf("%w: %q", ErrNonEmptyLayoutDirectory, layoutDir)
		}
	case os.IsNotExist(err):
		if mkErr := os.MkdirAll(layoutDir, layoutDirMode); mkErr != nil {
			return fmt.Errorf("create layout dir: %w", mkErr)
		}
	case err != nil:
		return fmt.Errorf("stat layout dir: %w", err)
	}

	if err := os.MkdirAll(filepath.Join(layoutDir, "blobs"), layoutDirMode); err != nil {
		return fmt.Errorf("create blobs dir: %w", err)
	}

	return nil
}

func isDirEmpty(dir string) (bool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false, fmt.Errorf("read layout dir: %w", err)
	}

	return len(entries) == 0, nil
}

func writeLayoutBlob(layoutDir, digest string, data []byte) error {
	algorithm, encoded, err := splitDigest(digest)
	if err != nil {
		return err
	}

	blobDir := filepath.Join(layoutDir, "blobs", algorithm)
	if err := os.MkdirAll(blobDir, layoutDirMode); err != nil {
		return fmt.Errorf("create blob dir: %w", err)
	}

	if err := os.WriteFile(filepath.Join(blobDir, encoded), data, layoutFileMode); err != nil {
		return fmt.Errorf("write blob: %w", err)
	}

	return nil
}

func readLayoutBlob(layoutDir, digest string) ([]byte, error) {
	algorithm, encoded, err := splitDigest(digest)
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(filepath.Join(layoutDir, "blobs", algorithm, encoded))
	if err != nil {
		return nil, fmt.Errorf("read blob %q: %w", digest, err)
	}

	return data, nil
}

func readLayoutJSONBlob(layoutDir, digest string, target any) error {
	data, err := readLayoutBlob(layoutDir, digest)
	if err != nil {
		return err
	}

	if err := json.Unmarshal(data, target); err != nil {
		return fmt.Errorf("parse blob %q: %w", digest, err)
	}

	return nil
}

func readLayoutFile(path string, target any) error {
	data, err := os.ReadFile(path) //nolint:gosec // path is derived from a caller-provided layout directory.
	if err != nil {
		return fmt.Errorf("read %q: %w", filepath.Base(path), err)
	}

	if err := json.Unmarshal(data, target); err != nil {
		return fmt.Errorf("parse %q: %w", filepath.Base(path), err)
	}

	return nil
}

func loadManifestBlobs(layoutDir string, manifest *OCIImageManifest, blobs map[string][]byte) error {
	if err := loadBlob(layoutDir, manifest.Config.Digest, blobs); err != nil {
		return err
	}

	for _, layer := range manifest.Layers {
		if err := loadBlob(layoutDir, layer.Digest, blobs); err != nil {
			return err
		}
	}

	return nil
}

func loadBlob(layoutDir, digest string, blobs map[string][]byte) error {
	if _, ok := blobs[digest]; ok {
		return nil
	}

	data, err := readLayoutBlob(layoutDir, digest)
	if err != nil {
		return err
	}

	blobs[digest] = data

	return nil
}

// splitDigest splits "algorithm:encoded" and rejects values that could escape
// the blobs directory (path traversal hardening).
func splitDigest(digest string) (string, string, error) {
	algorithm, encoded, found := strings.Cut(digest, ":")
	if !found || algorithm == "" || encoded == "" {
		return "", "", fmt.Errorf("%w: %q", ErrInvalidDigest, digest)
	}

	if strings.ContainsAny(algorithm, `/\.`) || strings.ContainsAny(encoded, `/\.`) {
		return "", "", fmt.Errorf("%w: %q", ErrInvalidDigest, digest)
	}

	return algorithm, encoded, nil
}
