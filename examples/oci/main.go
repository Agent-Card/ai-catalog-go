// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

// Command oci-example packs an AI Catalog document into a standard OCI image
// layout on disk.
//
// Packaging a catalog as an OCI artifact is NOT part of the AI Catalog
// specification — it is only an informative "mapping to OCI". It is therefore
// intentionally kept out of the SDK and shown here as a self-contained example
// that depends solely on the standard library and the catalog package. Adapt or
// copy it; production use likely wants a real OCI client (e.g. oras) for
// distribution and cosign for signing.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/agntcy/ai-catalog-go/catalog"
)

const (
	ociLayoutVersion = "1.0.0"

	mediaTypeIndex    = "application/vnd.oci.image.index.v1+json"
	mediaTypeManifest = "application/vnd.oci.image.manifest.v1+json"
	mediaTypeEmpty    = "application/vnd.oci.empty.v1+json"
	mediaTypeCatalog  = "application/ai-catalog+json"

	refNameAnnotation = "org.opencontainers.image.ref.name"

	ociSchemaVersion = 2

	dirMode  os.FileMode = 0o755
	fileMode os.FileMode = 0o644
)

// descriptor references content by digest (a subset of the OCI content
// descriptor schema).
type descriptor struct {
	MediaType    string            `json:"mediaType"`
	Digest       string            `json:"digest"`
	Size         int               `json:"size"`
	ArtifactType string            `json:"artifactType,omitempty"`
	Annotations  map[string]string `json:"annotations,omitempty"`
}

type manifest struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType"`
	ArtifactType  string       `json:"artifactType,omitempty"`
	Config        descriptor   `json:"config"`
	Layers        []descriptor `json:"layers"`
}

type index struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType"`
	Manifests     []descriptor `json:"manifests"`
}

func main() {
	dir, err := os.MkdirTemp("", "ai-catalog-oci-*")
	if err != nil {
		log.Fatalf("create output dir: %v", err)
	}

	if err := run(dir); err != nil {
		log.Fatalf("pack catalog: %v", err)
	}

	log.Printf("wrote OCI image layout to %s", dir)
}

// run packs a sample catalog into an OCI image layout rooted at dir.
func run(dir string) error {
	doc := sampleCatalog()

	blobs := filepath.Join(dir, "blobs", "sha256")
	if err := os.MkdirAll(blobs, dirMode); err != nil {
		return fmt.Errorf("create blobs dir: %w", err)
	}

	// The catalog document becomes the single layer; an empty JSON object
	// serves as the (required) config, following OCI's artifact conventions.
	catalogBytes, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("marshal catalog: %w", err)
	}

	layer, err := writeBlob(blobs, catalogBytes, mediaTypeCatalog)
	if err != nil {
		return err
	}

	config, err := writeBlob(blobs, []byte("{}"), mediaTypeEmpty)
	if err != nil {
		return err
	}

	man := manifest{
		SchemaVersion: ociSchemaVersion,
		MediaType:     mediaTypeManifest,
		ArtifactType:  mediaTypeCatalog,
		Config:        config,
		Layers:        []descriptor{layer},
	}

	manBytes, err := json.Marshal(man)
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}

	manDesc, err := writeBlob(blobs, manBytes, mediaTypeManifest)
	if err != nil {
		return err
	}

	manDesc.ArtifactType = mediaTypeCatalog
	manDesc.Annotations = map[string]string{refNameAnnotation: doc.SpecVersion}

	idx := index{
		SchemaVersion: ociSchemaVersion,
		MediaType:     mediaTypeIndex,
		Manifests:     []descriptor{manDesc},
	}

	if err := writeJSON(filepath.Join(dir, "index.json"), idx); err != nil {
		return err
	}

	return writeJSON(filepath.Join(dir, "oci-layout"),
		map[string]string{"imageLayoutVersion": ociLayoutVersion})
}

// writeBlob writes data into the content-addressable blobs/sha256 directory and
// returns a descriptor pointing at it.
func writeBlob(blobsDir string, data []byte, mediaType string) (descriptor, error) {
	sum := sha256.Sum256(data)
	hexSum := hex.EncodeToString(sum[:])

	if err := os.WriteFile(filepath.Join(blobsDir, hexSum), data, fileMode); err != nil {
		return descriptor{}, fmt.Errorf("write blob %s: %w", hexSum, err)
	}

	return descriptor{
		MediaType: mediaType,
		Digest:    "sha256:" + hexSum,
		Size:      len(data),
	}, nil
}

// writeJSON marshals v and writes it to path.
func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal %s: %w", filepath.Base(path), err)
	}

	if err := os.WriteFile(path, data, fileMode); err != nil {
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}

	return nil
}

// sampleCatalog builds a small, valid AI Catalog to package.
func sampleCatalog() *catalog.AICatalog {
	return &catalog.AICatalog{
		SpecVersion: "1.0",
		Host:        &catalog.HostInfo{Identifier: "did:web:acme-corp.com"},
		Entries: []catalog.CatalogEntry{
			{
				Identifier:  "urn:air:acme-corp.com:mcp:weather",
				DisplayName: "Weather",
				Type:        "application/mcp-server-card+json",
				URL:         "https://acme-corp.com/mcp/weather",
			},
		},
	}
}
