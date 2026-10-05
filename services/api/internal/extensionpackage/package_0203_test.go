package extensionpackage

import (
	"archive/zip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

func writeRegistryTestEntry0203(t *testing.T, zw *zip.Writer, name string, data []byte, mode os.FileMode, when time.Time) {
	t.Helper()
	h := &zip.FileHeader{Name: name, Method: zip.Deflate}
	h.SetMode(mode)
	h.SetModTime(when)
	w, err := zw.CreateHeader(h)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
}

func buildRegistryTestPackage0203(t *testing.T, creatorVersion string) (string, ed25519.PublicKey) {
	t.Helper()
	manifest, canonicalDigest, err := repository.NormalizeExtensionManifest(model.ExtensionManifest{
		SchemaVersion: "2.0", ID: "example.registry-extension", Name: "Registry Extension", Version: "1.2.3", Publisher: "deeplayer.team", API: "1.0",
		Targets: []model.ExtensionTarget{{Kind: "backend", Entrypoint: "backend/extension"}}, Permissions: []string{"project:read"},
	})
	if err != nil {
		t.Fatal(err)
	}
	manifestBytes, err := canonicalJSON0203(manifest)
	if err != nil {
		t.Fatal(err)
	}
	payloadBytes := []byte("#!/bin/sh\necho registry\n")
	payloadDigest := sha256.Sum256(payloadBytes)
	payloadFile := PackageFile{Path: "backend/extension", Size: int64(len(payloadBytes)), SHA256: hex.EncodeToString(payloadDigest[:]), Mode: "0755"}
	payload := PackagePayload{FileCount: 1, TotalBytes: int64(len(payloadBytes)), Files: []PackageFile{payloadFile}}
	manifestDigest := sha256.Sum256(manifestBytes)
	checksumsBytes := checksumBytes0203(hex.EncodeToString(manifestDigest[:]), payload.Files)
	buildTime := time.Unix(1791195900, 0).UTC() // 2026-10-05, even second for ZIP timestamp round-trip.
	pathDigest := sha256.Sum256([]byte(payloadFile.Path))
	fileID := "SPDXRef-File-" + hex.EncodeToString(pathDigest[:8])
	sbom := spdxDocument0203{
		SPDXVersion: "SPDX-2.3", DataLicense: "CC0-1.0", SPDXID: "SPDXRef-DOCUMENT", Name: manifest.ID + " " + manifest.Version,
		DocumentNamespace: "https://neverlauncher.local/spdx/extension/" + manifest.ID + "/" + manifest.Version + "/" + canonicalDigest,
		CreationInfo:      spdxCreationInfo0203{Created: buildTime.Format(time.RFC3339), Creators: []string{"Tool: NeverLauncher CLI " + creatorVersion}},
		Packages:          []spdxPackage0203{{SPDXID: "SPDXRef-Package-Extension", Name: manifest.Name, VersionInfo: manifest.Version, DownloadLocation: "NOASSERTION", FilesAnalyzed: true, LicenseConcluded: "NOASSERTION", LicenseDeclared: "NOASSERTION"}},
		Files:             []spdxFile0203{{SPDXID: fileID, FileName: "./payload/" + payloadFile.Path, Checksums: []spdxChecksum0203{{Algorithm: "SHA256", ChecksumValue: payloadFile.SHA256}}}},
		Relationships:     []spdxRelationship0203{{SPDXElementID: "SPDXRef-DOCUMENT", RelationshipType: "DESCRIBES", RelatedSPDXElement: "SPDXRef-Package-Extension"}, {SPDXElementID: "SPDXRef-Package-Extension", RelationshipType: "CONTAINS", RelatedSPDXElement: fileID}},
	}
	sbomBytes, err := canonicalJSON0203(sbom)
	if err != nil {
		t.Fatal(err)
	}
	checksumsDigest, sbomDigest := sha256.Sum256(checksumsBytes), sha256.Sum256(sbomBytes)
	descriptor, err := buildDescriptor0203(manifest, buildTime.Unix(), hex.EncodeToString(manifestDigest[:]), canonicalDigest, hex.EncodeToString(checksumsDigest[:]), hex.EncodeToString(sbomDigest[:]), payload)
	if err != nil {
		t.Fatal(err)
	}
	descriptorBytes, err := canonicalJSON0203(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyDigest := sha256.Sum256(public)
	signature := Signature{SchemaVersion: "1.0", Algorithm: "Ed25519", SigningDomain: signingDomain0203(), PackageIdentity: descriptor.PackageIdentity, KeyFingerprint: "sha256:" + hex.EncodeToString(keyDigest[:]), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(private, signingMessage0203(descriptor.PackageIdentity)))}
	signatureBytes, err := canonicalJSON0203(signature)
	if err != nil {
		t.Fatal(err)
	}

	filePath := filepath.Join(t.TempDir(), "registry.nlext")
	file, err := os.Create(filePath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(file)
	writeRegistryTestEntry0203(t, zw, manifestName0203, manifestBytes, 0o644, buildTime)
	writeRegistryTestEntry0203(t, zw, payloadPrefix0203+payloadFile.Path, payloadBytes, 0o755, buildTime)
	writeRegistryTestEntry0203(t, zw, checksumsName0203, checksumsBytes, 0o644, buildTime)
	writeRegistryTestEntry0203(t, zw, sbomName0203, sbomBytes, 0o644, buildTime)
	writeRegistryTestEntry0203(t, zw, descriptorName0203, descriptorBytes, 0o644, buildTime)
	writeRegistryTestEntry0203(t, zw, signatureName0203, signatureBytes, 0o644, buildTime)
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return filePath, public
}

func TestVerifyRegistryPackageAcceptsOlderCLISBOM0203(t *testing.T) {
	packagePath, public := buildRegistryTestPackage0203(t, "0.20.2")
	inspected, err := InspectSignedFile(packagePath)
	if err != nil {
		t.Fatal(err)
	}
	if inspected.Manifest.ID != "example.registry-extension" || inspected.KeyFingerprint == "" {
		t.Fatalf("inspect=%+v", inspected)
	}
	verified, err := VerifyFile(packagePath, public)
	if err != nil {
		t.Fatal(err)
	}
	if verified.PackageIdentity != inspected.PackageIdentity || verified.SHA256 != inspected.SHA256 || verified.Size != inspected.Size {
		t.Fatalf("verify/inspect mismatch")
	}
	otherPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyFile(packagePath, otherPublic); err == nil {
		t.Fatal("VerifyFile accepted an untrusted Ed25519 key")
	}
}
