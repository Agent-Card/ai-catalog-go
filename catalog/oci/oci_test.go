// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package oci_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/agntcy/ai-catalog-go-sdk/catalog"
	"github.com/agntcy/ai-catalog-go-sdk/catalog/oci"
)

const inlineWithTrust = `{
	"specVersion": "1.0",
	"metadata": {"scope": "test"},
	"entries": [
		{
			"identifier": "urn:example:inline",
			"displayName": "Inline Entry",
			"type": "application/json",
			"data": {"name": "inline"},
			"trustManifest": {"identity": "urn:example:inline"}
		}
	]
}`

const externalCatalog = `{
	"specVersion": "1.0",
	"host": {"displayName": "Example Host"},
	"metadata": {"scope": "demo"},
	"entries": [
		{
			"identifier": "urn:example:url",
			"displayName": "External Entry",
			"type": "application/json",
			"url": "https://example.com/entry.json"
		}
	]
}`

func mustParse(t *testing.T, doc string) *catalog.AICatalog {
	t.Helper()

	c, err := catalog.ParseString(doc)
	if err != nil {
		t.Fatalf("parse document: %v", err)
	}

	return c
}

func assertRoundTrip(t *testing.T, doc string) {
	t.Helper()

	original := mustParse(t, doc)

	set, err := oci.PackCatalog(original)
	if err != nil {
		t.Fatalf("PackCatalog error: %v", err)
	}

	unpacked, err := oci.UnpackCatalog(set)
	if err != nil {
		t.Fatalf("UnpackCatalog error: %v", err)
	}

	assertCatalogsEqual(t, original, unpacked)
}

func assertCatalogsEqual(t *testing.T, want, got *catalog.AICatalog) {
	t.Helper()

	wantJSON, err := want.ToJSON()
	if err != nil {
		t.Fatalf("marshal want: %v", err)
	}

	gotJSON, err := got.ToJSON()
	if err != nil {
		t.Fatalf("marshal got: %v", err)
	}

	var wantAny, gotAny any
	_ = json.Unmarshal(wantJSON, &wantAny)
	_ = json.Unmarshal(gotJSON, &gotAny)

	if !reflect.DeepEqual(wantAny, gotAny) {
		t.Errorf("catalog round-trip mismatch:\n want %s\n  got %s", wantJSON, gotJSON)
	}
}

func TestPackUnpack_InlineWithTrust(t *testing.T) {
	assertRoundTrip(t, inlineWithTrust)
}

func TestPackUnpack_External(t *testing.T) {
	assertRoundTrip(t, externalCatalog)
}

func TestPack_IndexAndReferrer(t *testing.T) {
	set, err := oci.PackCatalog(mustParse(t, inlineWithTrust))
	if err != nil {
		t.Fatalf("PackCatalog error: %v", err)
	}

	if set.Index.ArtifactType != oci.AICatalogMediaType {
		t.Errorf("index artifactType = %q", set.Index.ArtifactType)
	}

	if len(set.Index.Manifests) != 1 {
		t.Fatalf("index manifests = %d, want 1", len(set.Index.Manifests))
	}

	digest := set.Index.Manifests[0].Digest
	if len(set.Referrers[digest]) != 1 {
		t.Fatalf("referrers = %d, want 1", len(set.Referrers[digest]))
	}

	if set.Referrers[digest][0].ArtifactType != oci.TrustManifestArtifactType {
		t.Errorf("referrer artifactType = %q", set.Referrers[digest][0].ArtifactType)
	}
}

func TestPack_PreservesCatalogAnnotations(t *testing.T) {
	set, err := oci.PackCatalog(mustParse(t, externalCatalog))
	if err != nil {
		t.Fatalf("PackCatalog error: %v", err)
	}

	if set.Index.Annotations["ai-catalog.specVersion"] != "1.0" {
		t.Errorf("specVersion annotation = %q", set.Index.Annotations["ai-catalog.specVersion"])
	}

	for _, key := range []string{"ai-catalog.host", "ai-catalog.metadata"} {
		if _, ok := set.Index.Annotations[key]; !ok {
			t.Errorf("missing annotation %q", key)
		}
	}
}

func TestPack_RejectsInvalidContentShape(t *testing.T) {
	doc := `{
		"specVersion": "1.0",
		"entries": [
			{"identifier": "urn:example:missing", "displayName": "Missing", "type": "application/json"}
		]
	}`

	_, err := oci.PackCatalog(mustParse(t, doc))
	if !errors.Is(err, oci.ErrInvalidEntryContent) {
		t.Fatalf("error = %v, want ErrInvalidEntryContent", err)
	}
}

func TestUnpack_RejectsWrongIndexArtifactType(t *testing.T) {
	set, err := oci.PackCatalog(mustParse(t, externalCatalog))
	if err != nil {
		t.Fatalf("PackCatalog error: %v", err)
	}

	set.Index.ArtifactType = "application/other"

	if _, err := oci.UnpackCatalog(set); !errors.Is(err, oci.ErrUnsupportedIndexArtifact) {
		t.Fatalf("error = %v, want ErrUnsupportedIndexArtifact", err)
	}
}

func TestExportLayout_Standard(t *testing.T) {
	set, err := oci.PackCatalog(mustParse(t, externalCatalog))
	if err != nil {
		t.Fatalf("PackCatalog error: %v", err)
	}

	dir := filepath.Join(t.TempDir(), "layout")
	if err := set.ExportLayout(dir, "v1"); err != nil {
		t.Fatalf("ExportLayout error: %v", err)
	}

	var metadata map[string]any
	readJSON(t, filepath.Join(dir, "oci-layout"), &metadata)

	if metadata["imageLayoutVersion"] != oci.OCILayoutVersion {
		t.Errorf("imageLayoutVersion = %v", metadata["imageLayoutVersion"])
	}

	var index oci.OCIImageIndex
	readJSON(t, filepath.Join(dir, "index.json"), &index)

	if len(index.Manifests) != 1+len(set.Index.Manifests) {
		t.Errorf("layout index manifests = %d, want %d", len(index.Manifests), 1+len(set.Index.Manifests))
	}

	var root *oci.OCIDescriptor

	for i := range index.Manifests {
		if index.Manifests[i].Annotations[oci.OCIRefNameAnnotation] == "v1" {
			root = &index.Manifests[i]
		}
	}

	if root == nil {
		t.Fatal("root descriptor with ref name 'v1' not found")
	}
}

func TestExportLayout_RejectsEmptyTag(t *testing.T) {
	set, err := oci.PackCatalog(mustParse(t, externalCatalog))
	if err != nil {
		t.Fatalf("PackCatalog error: %v", err)
	}

	if err := set.ExportLayout(t.TempDir(), "   "); !errors.Is(err, oci.ErrInvalidLayoutTag) {
		t.Fatalf("error = %v, want ErrInvalidLayoutTag", err)
	}
}

func TestExportLayout_RejectsNonEmptyDirectory(t *testing.T) {
	set, err := oci.PackCatalog(mustParse(t, externalCatalog))
	if err != nil {
		t.Fatalf("PackCatalog error: %v", err)
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "stale.txt"), []byte("stale"), 0o600); err != nil {
		t.Fatalf("write stale file: %v", err)
	}

	if err := set.ExportLayout(dir, "latest"); !errors.Is(err, oci.ErrNonEmptyLayoutDirectory) {
		t.Fatalf("error = %v, want ErrNonEmptyLayoutDirectory", err)
	}
}

func TestExportImportLayout_RoundTrip(t *testing.T) {
	original := mustParse(t, externalCatalog)

	set, err := oci.PackCatalog(original)
	if err != nil {
		t.Fatalf("PackCatalog error: %v", err)
	}

	dir := filepath.Join(t.TempDir(), "layout")
	if err := set.ExportLayout(dir, "latest"); err != nil {
		t.Fatalf("ExportLayout error: %v", err)
	}

	imported, err := oci.ImportLayout(dir, "")
	if err != nil {
		t.Fatalf("ImportLayout error: %v", err)
	}

	if imported.Index.ArtifactType != oci.AICatalogMediaType {
		t.Errorf("imported index artifactType = %q", imported.Index.ArtifactType)
	}

	unpacked, err := oci.UnpackCatalog(imported)
	if err != nil {
		t.Fatalf("UnpackCatalog error: %v", err)
	}

	assertCatalogsEqual(t, original, unpacked)
}

func TestImportLayout_PreservesReferrers(t *testing.T) {
	set, err := oci.PackCatalog(mustParse(t, inlineWithTrust))
	if err != nil {
		t.Fatalf("PackCatalog error: %v", err)
	}

	entryDigest := set.Index.Manifests[0].Digest

	dir := filepath.Join(t.TempDir(), "layout")
	if err := set.ExportLayout(dir, "inline"); err != nil {
		t.Fatalf("ExportLayout error: %v", err)
	}

	imported, err := oci.ImportLayout(dir, "inline")
	if err != nil {
		t.Fatalf("ImportLayout error: %v", err)
	}

	if len(imported.Referrers[entryDigest]) != 1 {
		t.Fatalf("referrers = %d, want 1", len(imported.Referrers[entryDigest]))
	}

	if imported.Referrers[entryDigest][0].ArtifactType != oci.TrustManifestArtifactType {
		t.Errorf("referrer artifactType = %q", imported.Referrers[entryDigest][0].ArtifactType)
	}
}

func TestImportLayout_RejectsUnknownReference(t *testing.T) {
	set, err := oci.PackCatalog(mustParse(t, externalCatalog))
	if err != nil {
		t.Fatalf("PackCatalog error: %v", err)
	}

	dir := filepath.Join(t.TempDir(), "layout")
	if err := set.ExportLayout(dir, "latest"); err != nil {
		t.Fatalf("ExportLayout error: %v", err)
	}

	if _, err := oci.ImportLayout(dir, "missing"); !errors.Is(err, oci.ErrMissingLayoutReference) {
		t.Fatalf("error = %v, want ErrMissingLayoutReference", err)
	}
}

func TestAttachCosign_AndUnpack(t *testing.T) {
	set, err := oci.PackCatalog(mustParse(t, inlineWithTrust))
	if err != nil {
		t.Fatalf("PackCatalog error: %v", err)
	}

	entryDigest := set.Index.Manifests[0].Digest

	err = set.AttachCosignVerificationArtifacts(
		entryDigest, "urn:example:inline", "sha256:1234abcd",
		[]byte("cosign-signature"),
		[]byte("-----BEGIN PUBLIC KEY-----\nZmFrZQ==\n-----END PUBLIC KEY-----\n"))
	if err != nil {
		t.Fatalf("AttachCosignVerificationArtifacts error: %v", err)
	}

	if len(set.Referrers[entryDigest]) != 3 {
		t.Fatalf("referrers = %d, want 3", len(set.Referrers[entryDigest]))
	}

	if _, err := oci.UnpackCatalog(set); err != nil {
		t.Fatalf("UnpackCatalog error after cosign attach: %v", err)
	}
}

func TestAttachCosign_ExportImportReferrerTypes(t *testing.T) {
	set, err := oci.PackCatalog(mustParse(t, inlineWithTrust))
	if err != nil {
		t.Fatalf("PackCatalog error: %v", err)
	}

	entryDigest := set.Index.Manifests[0].Digest

	if err := set.AttachCosignVerificationArtifacts(
		entryDigest, "urn:example:inline", "sha256:1234abcd",
		[]byte("cosign-signature"),
		[]byte("-----BEGIN PUBLIC KEY-----\nZmFrZQ==\n-----END PUBLIC KEY-----\n")); err != nil {
		t.Fatalf("attach error: %v", err)
	}

	dir := filepath.Join(t.TempDir(), "layout")
	if err := set.ExportLayout(dir, "inline"); err != nil {
		t.Fatalf("ExportLayout error: %v", err)
	}

	imported, err := oci.ImportLayout(dir, "inline")
	if err != nil {
		t.Fatalf("ImportLayout error: %v", err)
	}

	types := map[string]bool{}
	for _, manifest := range imported.Referrers[entryDigest] {
		types[manifest.ArtifactType] = true
	}

	for _, want := range []string{
		oci.TrustManifestArtifactType,
		oci.CosignSignatureArtifactType,
		oci.CosignPublicKeyArtifactType,
	} {
		if !types[want] {
			t.Errorf("imported referrers missing artifact type %q", want)
		}
	}
}

func TestAttachCosign_MissingSubject(t *testing.T) {
	set, err := oci.PackCatalog(mustParse(t, externalCatalog))
	if err != nil {
		t.Fatalf("PackCatalog error: %v", err)
	}

	err = set.AttachCosignVerificationArtifacts(
		"sha256:deadbeef", "urn:example:x", "sha256:abcd", []byte("s"), []byte("k"))
	if !errors.Is(err, oci.ErrMissingSubjectDescriptor) {
		t.Fatalf("error = %v, want ErrMissingSubjectDescriptor", err)
	}
}

func readJSON(t *testing.T, path string, target any) {
	t.Helper()

	data, err := os.ReadFile(path) //nolint:gosec // test reads a file it just wrote.
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	if err := json.Unmarshal(data, target); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
}
