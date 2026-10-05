package main

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	extensionPackageFormat0202          = "NeverLauncher Extension Package"
	extensionPackageFormatVersion0202   = "1.0"
	extensionPackageManifestName0202    = canonicalExtensionManifestName0201
	extensionPackageChecksumsName0202   = "checksums.sha256"
	extensionPackageSBOMName0202        = "SBOM.spdx.json"
	extensionPackageDescriptorName0202  = "neverlauncher-package.json"
	extensionPackageSignatureName0202   = "signature.ed25519"
	extensionPackagePayloadPrefix0202   = "payload/"
	extensionPackageMaxFiles0202        = 10000
	extensionPackageMaxSingleFile0202   = int64(512 << 20)
	extensionPackageMaxTotalBytes0202   = int64(2 << 30)
	extensionPackageMaxMetadata0202     = int64(8 << 20)
	extensionPackageMaxCompressionRatio = uint64(10000)
)

var extensionPackageReservedRoot0202 = map[string]struct{}{
	extensionPackageManifestName0202:   {},
	extensionPackageChecksumsName0202:  {},
	extensionPackageSBOMName0202:       {},
	extensionPackageDescriptorName0202: {},
	extensionPackageSignatureName0202:  {},
}

type ExtensionPackageFile0202 struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	Mode   string `json:"mode"`
}

type ExtensionPackagePayload0202 struct {
	FileCount  int                        `json:"fileCount"`
	TotalBytes int64                      `json:"totalBytes"`
	Files      []ExtensionPackageFile0202 `json:"files"`
}

type ExtensionPackageDescriptor0202 struct {
	Format                  string                      `json:"format"`
	FormatVersion           string                      `json:"formatVersion"`
	ExtensionID             string                      `json:"extensionId"`
	ExtensionVersion        string                      `json:"extensionVersion"`
	Publisher               string                      `json:"publisher"`
	API                     string                      `json:"api"`
	BuildEpoch              int64                       `json:"buildEpoch"`
	PackageIdentity         string                      `json:"packageIdentity"`
	ManifestSHA256          string                      `json:"manifestSha256"`
	CanonicalManifestSHA256 string                      `json:"canonicalManifestSha256"`
	ChecksumsSHA256         string                      `json:"checksumsSha256"`
	SBOMSHA256              string                      `json:"sbomSha256"`
	Payload                 ExtensionPackagePayload0202 `json:"payload"`
}

type extensionPackageIdentityMaterial0202 struct {
	Format                  string                      `json:"format"`
	FormatVersion           string                      `json:"formatVersion"`
	ExtensionID             string                      `json:"extensionId"`
	ExtensionVersion        string                      `json:"extensionVersion"`
	Publisher               string                      `json:"publisher"`
	API                     string                      `json:"api"`
	BuildEpoch              int64                       `json:"buildEpoch"`
	ManifestSHA256          string                      `json:"manifestSha256"`
	CanonicalManifestSHA256 string                      `json:"canonicalManifestSha256"`
	ChecksumsSHA256         string                      `json:"checksumsSha256"`
	SBOMSHA256              string                      `json:"sbomSha256"`
	Payload                 ExtensionPackagePayload0202 `json:"payload"`
}

type ExtensionPackageSignature0202 struct {
	SchemaVersion   string `json:"schemaVersion"`
	Algorithm       string `json:"algorithm"`
	SigningDomain   string `json:"signingDomain"`
	PackageIdentity string `json:"packageIdentity"`
	KeyFingerprint  string `json:"keyFingerprint"`
	Signature       string `json:"signature"`
}

type extensionPackageSourceFile0202 struct {
	Rel  string
	Abs  string
	Mode os.FileMode
	Size int64
}

type extensionPackageAnalysis0202 struct {
	Path            string
	Reader          *zip.ReadCloser
	Entries         map[string]*zip.File
	Manifest        CanonicalExtensionManifest0201
	ManifestBytes   []byte
	CanonicalDigest string
	ChecksumsBytes  []byte
	SBOMBytes       []byte
	DescriptorBytes []byte
	Descriptor      ExtensionPackageDescriptor0202
	SignatureBytes  []byte
	Signature       *ExtensionPackageSignature0202
}

func (a *extensionPackageAnalysis0202) Close() error {
	if a == nil || a.Reader == nil {
		return nil
	}
	return a.Reader.Close()
}

func handleExtensionPackage0202(args []string) error {
	if len(args) == 0 {
		return errors.New("extension package command missing")
	}
	switch args[0] {
	case "pack":
		if len(args) < 2 || strings.HasPrefix(args[1], "--") {
			return errors.New("extension pack требует каталог extension")
		}
		source := args[1]
		manifest, _, _, err := loadCanonicalExtension0201(source)
		if err != nil {
			return err
		}
		out := strings.TrimSpace(flagValue(args[2:], "--output", ""))
		if out == "" {
			out = manifest.ID + "-" + manifest.Version + ".nlext"
		}
		result, err := packExtensionPackage0202(source, out)
		if err != nil {
			return err
		}
		if privateKeyPath := strings.TrimSpace(flagValue(args[2:], "--private-key", "")); privateKeyPath != "" {
			result, err = signExtensionPackage0202(out, out, privateKeyPath, false)
			if err != nil {
				return err
			}
		}
		printJSON(result)
		return nil
	case "sign":
		if len(args) < 2 || strings.HasPrefix(args[1], "--") {
			return errors.New("extension sign требует путь к .nlext")
		}
		packagePath := args[1]
		out := strings.TrimSpace(flagValue(args[2:], "--output", packagePath))
		privateKeyPath := strings.TrimSpace(flagValue(args[2:], "--private-key", ""))
		if privateKeyPath == "" {
			privateKeyPath = strings.TrimSpace(os.Getenv("NEVERLAUNCHER_EXTENSION_SIGNING_PRIVATE_KEY_FILE"))
		}
		if privateKeyPath == "" {
			return errors.New("extension sign требует --private-key или NEVERLAUNCHER_EXTENSION_SIGNING_PRIVATE_KEY_FILE")
		}
		result, err := signExtensionPackage0202(packagePath, out, privateKeyPath, flagBool(args[2:], "--force", false))
		if err != nil {
			return err
		}
		printJSON(result)
		return nil
	case "verify":
		if len(args) < 2 || strings.HasPrefix(args[1], "--") {
			return errors.New("extension verify требует путь к .nlext")
		}
		publicKeyPath := strings.TrimSpace(flagValue(args[2:], "--public-key", ""))
		if publicKeyPath == "" {
			publicKeyPath = strings.TrimSpace(os.Getenv("NEVERLAUNCHER_EXTENSION_SIGNING_PUBLIC_KEY_FILE"))
		}
		result, err := verifyExtensionPackage0202(args[1], publicKeyPath, flagBool(args[2:], "--allow-unsigned", false))
		if err != nil {
			return err
		}
		printJSON(result)
		return nil
	case "inspect":
		if len(args) < 2 || strings.HasPrefix(args[1], "--") {
			return errors.New("extension inspect требует путь к .nlext")
		}
		result, err := inspectExtensionPackage0202(args[1], flagBool(args[2:], "--files", false))
		if err != nil {
			return err
		}
		printJSON(result)
		return nil
	default:
		return fmt.Errorf("неизвестная extension package-подкоманда: %s", args[0])
	}
}

func packExtensionPackage0202(sourceDir, outputPath string) (map[string]any, error) {
	sourceAbs, err := filepath.Abs(filepath.Clean(sourceDir))
	if err != nil {
		return nil, err
	}
	rootInfo, err := os.Lstat(sourceAbs)
	if err != nil {
		return nil, err
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return nil, errors.New("extension source должен быть обычным каталогом, не symlink")
	}
	if strings.ToLower(filepath.Ext(outputPath)) != ".nlext" {
		return nil, errors.New("extension package output должен иметь расширение .nlext")
	}
	outputAbs, err := filepath.Abs(filepath.Clean(outputPath))
	if err != nil {
		return nil, err
	}

	manifest, _, canonicalDigest, err := loadCanonicalExtension0201(sourceAbs)
	if err != nil {
		return nil, err
	}
	manifestBytes, err := canonicalExtensionManifestBytes0202(manifest)
	if err != nil {
		return nil, err
	}

	sourceFiles, err := collectExtensionPayload0202(sourceAbs, outputAbs)
	if err != nil {
		return nil, err
	}
	if len(sourceFiles) == 0 {
		return nil, errors.New("extension payload пуст")
	}
	if err := ensureExtensionEntrypointsPresent0202(manifest, sourceFiles); err != nil {
		return nil, err
	}

	if err := os.MkdirAll(filepath.Dir(outputAbs), 0o755); err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(outputAbs), ".nlext-pack-*.tmp")
	if err != nil {
		return nil, err
	}
	tmpPath := tmp.Name()
	ok := false
	defer func() {
		_ = tmp.Close()
		if !ok {
			_ = os.Remove(tmpPath)
		}
	}()

	buildTime := deterministicExtensionBuildTime0202()
	zw := zip.NewWriter(tmp)
	if err := writeDeterministicZipBytes0202(zw, extensionPackageManifestName0202, manifestBytes, 0o644, buildTime); err != nil {
		_ = zw.Close()
		return nil, err
	}
	manifestStoredDigest := sha256.Sum256(manifestBytes)

	payload := ExtensionPackagePayload0202{Files: make([]ExtensionPackageFile0202, 0, len(sourceFiles))}
	for _, src := range sourceFiles {
		entry, err := writeDeterministicZipSource0202(zw, src, buildTime)
		if err != nil {
			_ = zw.Close()
			return nil, err
		}
		payload.Files = append(payload.Files, entry)
		payload.FileCount++
		payload.TotalBytes += entry.Size
		if payload.TotalBytes > extensionPackageMaxTotalBytes0202 {
			_ = zw.Close()
			return nil, fmt.Errorf("extension payload превышает лимит %d bytes", extensionPackageMaxTotalBytes0202)
		}
	}

	checksumsBytes := extensionChecksumsBytes0202(hex.EncodeToString(manifestStoredDigest[:]), payload.Files)
	if err := writeDeterministicZipBytes0202(zw, extensionPackageChecksumsName0202, checksumsBytes, 0o644, buildTime); err != nil {
		_ = zw.Close()
		return nil, err
	}
	sbomBytes, err := extensionSBOMBytes0202(manifest, canonicalDigest, payload, buildTime)
	if err != nil {
		_ = zw.Close()
		return nil, err
	}
	if err := writeDeterministicZipBytes0202(zw, extensionPackageSBOMName0202, sbomBytes, 0o644, buildTime); err != nil {
		_ = zw.Close()
		return nil, err
	}

	checksumsDigest := sha256.Sum256(checksumsBytes)
	sbomDigest := sha256.Sum256(sbomBytes)
	descriptor, err := buildExtensionPackageDescriptor0202(manifest, buildTime.Unix(), hex.EncodeToString(manifestStoredDigest[:]), canonicalDigest, hex.EncodeToString(checksumsDigest[:]), hex.EncodeToString(sbomDigest[:]), payload)
	if err != nil {
		_ = zw.Close()
		return nil, err
	}
	descriptorBytes, err := marshalCanonicalPrettyJSON0202(descriptor)
	if err != nil {
		_ = zw.Close()
		return nil, err
	}
	if err := writeDeterministicZipBytes0202(zw, extensionPackageDescriptorName0202, descriptorBytes, 0o644, buildTime); err != nil {
		_ = zw.Close()
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	if err := tmp.Sync(); err != nil {
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	if err := replaceFileAtomically0202(tmpPath, outputAbs, 0o644); err != nil {
		return nil, err
	}
	ok = true

	packageDigest, packageSize, err := hashFile(outputAbs)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"formatVersion":   extensionPackageFormatVersion0202,
		"packed":          true,
		"signed":          false,
		"path":            outputPath,
		"extensionId":     manifest.ID,
		"version":         manifest.Version,
		"packageIdentity": descriptor.PackageIdentity,
		"sha256":          packageDigest,
		"size":            packageSize,
		"payloadFiles":    payload.FileCount,
		"payloadBytes":    payload.TotalBytes,
	}, nil
}

func collectExtensionPayload0202(root, outputAbs string) ([]extensionPackageSourceFile0202, error) {
	files := make([]extensionPackageSourceFile0202, 0)
	seen := map[string]string{}
	total := int64(0)
	err := filepath.WalkDir(root, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if current == root {
			return nil
		}
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink запрещён в extension package source: %s", current)
		}
		if info.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("special file запрещён в extension package source: %s (%s)", current, info.Mode())
		}
		currentAbs, err := filepath.Abs(current)
		if err != nil {
			return err
		}
		if filepath.Clean(currentAbs) == filepath.Clean(outputAbs) {
			return nil
		}
		rel, err := filepath.Rel(root, currentAbs)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == extensionPackageManifestName0202 {
			return nil
		}
		if !strings.Contains(rel, "/") {
			if _, reserved := extensionPackageReservedRoot0202[rel]; reserved {
				return fmt.Errorf("source содержит зарезервированный package-файл %s", rel)
			}
		}
		packagePath := extensionPackagePayloadPrefix0202 + rel
		if err := validateExtensionArchivePath0202(packagePath); err != nil {
			return fmt.Errorf("payload path %q: %w", rel, err)
		}
		fold := strings.ToLower(packagePath)
		if previous, exists := seen[fold]; exists {
			return fmt.Errorf("case-insensitive duplicate payload path: %s и %s", previous, packagePath)
		}
		seen[fold] = packagePath
		if info.Size() > extensionPackageMaxSingleFile0202 {
			return fmt.Errorf("payload file %s превышает лимит %d bytes", rel, extensionPackageMaxSingleFile0202)
		}
		total += info.Size()
		if total > extensionPackageMaxTotalBytes0202 {
			return fmt.Errorf("extension payload превышает лимит %d bytes", extensionPackageMaxTotalBytes0202)
		}
		files = append(files, extensionPackageSourceFile0202{Rel: rel, Abs: currentAbs, Mode: normalizedExtensionMode0202(info.Mode()), Size: info.Size()})
		if len(files) > extensionPackageMaxFiles0202 {
			return fmt.Errorf("extension payload превышает лимит %d files", extensionPackageMaxFiles0202)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Rel < files[j].Rel })
	return files, nil
}

func ensureExtensionEntrypointsPresent0202(manifest CanonicalExtensionManifest0201, files []extensionPackageSourceFile0202) error {
	present := make(map[string]struct{}, len(files))
	for _, file := range files {
		present[file.Rel] = struct{}{}
	}
	for _, target := range manifest.Targets {
		if _, ok := present[target.Entrypoint]; !ok {
			return fmt.Errorf("target %s entrypoint %q отсутствует в payload", target.Kind, target.Entrypoint)
		}
	}
	return nil
}

func normalizedExtensionMode0202(mode os.FileMode) os.FileMode {
	if mode.Perm()&0o111 != 0 {
		return 0o755
	}
	return 0o644
}

func deterministicExtensionBuildTime0202() time.Time {
	const minZipEpoch = int64(315532800) // 1980-01-01T00:00:00Z
	epoch := minZipEpoch
	if raw := strings.TrimSpace(os.Getenv("SOURCE_DATE_EPOCH")); raw != "" {
		if parsed, err := strconv.ParseInt(raw, 10, 64); err == nil && parsed >= minZipEpoch {
			epoch = parsed
		}
	}
	return time.Unix(epoch, 0).UTC()
}

func canonicalExtensionManifestBytes0202(manifest CanonicalExtensionManifest0201) ([]byte, error) {
	normalized, _, err := normalizeCanonicalExtension0201(manifest)
	if err != nil {
		return nil, err
	}
	return marshalCanonicalPrettyJSON0202(normalized)
}

func marshalCanonicalPrettyJSON0202(value any) ([]byte, error) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func writeDeterministicZipBytes0202(zw *zip.Writer, name string, data []byte, mode os.FileMode, modified time.Time) error {
	if err := validateExtensionArchivePath0202(name); err != nil {
		return err
	}
	header := &zip.FileHeader{Name: name, Method: zip.Deflate}
	header.SetMode(mode)
	header.SetModTime(modified)
	header.Comment = ""
	header.Extra = nil
	header.NonUTF8 = false
	writer, err := zw.CreateHeader(header)
	if err != nil {
		return err
	}
	_, err = writer.Write(data)
	return err
}

func writeDeterministicZipSource0202(zw *zip.Writer, src extensionPackageSourceFile0202, modified time.Time) (ExtensionPackageFile0202, error) {
	before, err := os.Lstat(src.Abs)
	if err != nil {
		return ExtensionPackageFile0202{}, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return ExtensionPackageFile0202{}, fmt.Errorf("payload file changed type during packaging: %s", src.Rel)
	}
	file, err := os.Open(src.Abs)
	if err != nil {
		return ExtensionPackageFile0202{}, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return ExtensionPackageFile0202{}, err
	}
	if !os.SameFile(before, opened) {
		return ExtensionPackageFile0202{}, fmt.Errorf("payload file changed during packaging: %s", src.Rel)
	}
	if opened.Size() > extensionPackageMaxSingleFile0202 {
		return ExtensionPackageFile0202{}, fmt.Errorf("payload file %s превышает лимит %d bytes", src.Rel, extensionPackageMaxSingleFile0202)
	}
	archiveName := extensionPackagePayloadPrefix0202 + src.Rel
	header := &zip.FileHeader{Name: archiveName, Method: zip.Deflate}
	header.SetMode(src.Mode)
	header.SetModTime(modified)
	header.Comment = ""
	header.Extra = nil
	header.NonUTF8 = false
	writer, err := zw.CreateHeader(header)
	if err != nil {
		return ExtensionPackageFile0202{}, err
	}
	hash := sha256.New()
	written, err := io.Copy(io.MultiWriter(writer, hash), io.LimitReader(file, extensionPackageMaxSingleFile0202+1))
	if err != nil {
		return ExtensionPackageFile0202{}, err
	}
	if written != opened.Size() {
		return ExtensionPackageFile0202{}, fmt.Errorf("payload file changed size during packaging: %s", src.Rel)
	}
	return ExtensionPackageFile0202{Path: src.Rel, Size: written, SHA256: hex.EncodeToString(hash.Sum(nil)), Mode: fmt.Sprintf("%04o", src.Mode.Perm())}, nil
}

func extensionChecksumsBytes0202(manifestSHA string, files []ExtensionPackageFile0202) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "%s  %s\n", strings.ToLower(manifestSHA), extensionPackageManifestName0202)
	for _, file := range files {
		fmt.Fprintf(&b, "%s  %s%s\n", strings.ToLower(file.SHA256), extensionPackagePayloadPrefix0202, file.Path)
	}
	return []byte(b.String())
}

type extensionSPDXChecksum0202 struct {
	Algorithm     string `json:"algorithm"`
	ChecksumValue string `json:"checksumValue"`
}

type extensionSPDXFile0202 struct {
	SPDXID    string                      `json:"SPDXID"`
	FileName  string                      `json:"fileName"`
	Checksums []extensionSPDXChecksum0202 `json:"checksums"`
}

type extensionSPDXPackage0202 struct {
	SPDXID           string `json:"SPDXID"`
	Name             string `json:"name"`
	VersionInfo      string `json:"versionInfo"`
	DownloadLocation string `json:"downloadLocation"`
	FilesAnalyzed    bool   `json:"filesAnalyzed"`
	LicenseConcluded string `json:"licenseConcluded"`
	LicenseDeclared  string `json:"licenseDeclared"`
}

type extensionSPDXRelationship0202 struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
}

type extensionSPDXCreationInfo0202 struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type extensionSPDXDocument0202 struct {
	SPDXVersion       string                          `json:"spdxVersion"`
	DataLicense       string                          `json:"dataLicense"`
	SPDXID            string                          `json:"SPDXID"`
	Name              string                          `json:"name"`
	DocumentNamespace string                          `json:"documentNamespace"`
	CreationInfo      extensionSPDXCreationInfo0202   `json:"creationInfo"`
	Packages          []extensionSPDXPackage0202      `json:"packages"`
	Files             []extensionSPDXFile0202         `json:"files"`
	Relationships     []extensionSPDXRelationship0202 `json:"relationships"`
}

func extensionSBOMBytes0202(manifest CanonicalExtensionManifest0201, canonicalDigest string, payload ExtensionPackagePayload0202, buildTime time.Time) ([]byte, error) {
	pkgID := "SPDXRef-Package-Extension"
	doc := extensionSPDXDocument0202{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXID:            "SPDXRef-DOCUMENT",
		Name:              manifest.ID + " " + manifest.Version,
		DocumentNamespace: "https://neverlauncher.local/spdx/extension/" + manifest.ID + "/" + manifest.Version + "/" + canonicalDigest,
		CreationInfo:      extensionSPDXCreationInfo0202{Created: buildTime.Format(time.RFC3339), Creators: []string{"Tool: NeverLauncher CLI " + version}},
		Packages: []extensionSPDXPackage0202{{
			SPDXID: pkgID, Name: manifest.Name, VersionInfo: manifest.Version, DownloadLocation: "NOASSERTION", FilesAnalyzed: true, LicenseConcluded: "NOASSERTION", LicenseDeclared: "NOASSERTION",
		}},
		Files:         make([]extensionSPDXFile0202, 0, len(payload.Files)),
		Relationships: []extensionSPDXRelationship0202{{SPDXElementID: "SPDXRef-DOCUMENT", RelationshipType: "DESCRIBES", RelatedSPDXElement: pkgID}},
	}
	for _, file := range payload.Files {
		pathDigest := sha256.Sum256([]byte(file.Path))
		fileID := "SPDXRef-File-" + hex.EncodeToString(pathDigest[:8])
		doc.Files = append(doc.Files, extensionSPDXFile0202{SPDXID: fileID, FileName: "./" + extensionPackagePayloadPrefix0202 + file.Path, Checksums: []extensionSPDXChecksum0202{{Algorithm: "SHA256", ChecksumValue: file.SHA256}}})
		doc.Relationships = append(doc.Relationships, extensionSPDXRelationship0202{SPDXElementID: pkgID, RelationshipType: "CONTAINS", RelatedSPDXElement: fileID})
	}
	return marshalCanonicalPrettyJSON0202(doc)
}

func validateExtensionSBOM0203(data []byte, manifest CanonicalExtensionManifest0201, canonicalDigest string, payload ExtensionPackagePayload0202, buildTime time.Time) error {
	var doc extensionSPDXDocument0202
	if err := decodeStrictJSON0202(data, &doc); err != nil {
		return fmt.Errorf("decode SBOM.spdx.json: %w", err)
	}
	pkgID := "SPDXRef-Package-Extension"
	if doc.SPDXVersion != "SPDX-2.3" || doc.DataLicense != "CC0-1.0" || doc.SPDXID != "SPDXRef-DOCUMENT" || doc.Name != manifest.ID+" "+manifest.Version || doc.DocumentNamespace != "https://neverlauncher.local/spdx/extension/"+manifest.ID+"/"+manifest.Version+"/"+canonicalDigest {
		return errors.New("SBOM.spdx.json metadata не соответствует manifest")
	}
	if doc.CreationInfo.Created != buildTime.Format(time.RFC3339) || len(doc.CreationInfo.Creators) != 1 || !strings.HasPrefix(doc.CreationInfo.Creators[0], "Tool: NeverLauncher CLI ") {
		return errors.New("SBOM.spdx.json creationInfo некорректен")
	}
	if len(doc.Packages) != 1 {
		return errors.New("SBOM.spdx.json должен описывать один extension package")
	}
	pkg := doc.Packages[0]
	if pkg.SPDXID != pkgID || pkg.Name != manifest.Name || pkg.VersionInfo != manifest.Version || pkg.DownloadLocation != "NOASSERTION" || !pkg.FilesAnalyzed || pkg.LicenseConcluded != "NOASSERTION" || pkg.LicenseDeclared != "NOASSERTION" {
		return errors.New("SBOM.spdx.json package metadata не соответствует manifest")
	}
	if len(doc.Files) != len(payload.Files) || len(doc.Relationships) != len(payload.Files)+1 {
		return errors.New("SBOM.spdx.json file/relationship count не соответствует payload")
	}
	if doc.Relationships[0] != (extensionSPDXRelationship0202{SPDXElementID: "SPDXRef-DOCUMENT", RelationshipType: "DESCRIBES", RelatedSPDXElement: pkgID}) {
		return errors.New("SBOM.spdx.json DESCRIBES relationship некорректен")
	}
	for i, file := range payload.Files {
		pathDigest := sha256.Sum256([]byte(file.Path))
		fileID := "SPDXRef-File-" + hex.EncodeToString(pathDigest[:8])
		actual := doc.Files[i]
		if actual.SPDXID != fileID || actual.FileName != "./"+extensionPackagePayloadPrefix0202+file.Path || len(actual.Checksums) != 1 || actual.Checksums[0].Algorithm != "SHA256" || actual.Checksums[0].ChecksumValue != file.SHA256 {
			return fmt.Errorf("SBOM.spdx.json file entry %d не соответствует payload", i)
		}
		expectedRel := extensionSPDXRelationship0202{SPDXElementID: pkgID, RelationshipType: "CONTAINS", RelatedSPDXElement: fileID}
		if doc.Relationships[i+1] != expectedRel {
			return fmt.Errorf("SBOM.spdx.json relationship %d не соответствует payload", i+1)
		}
	}
	return nil
}

func buildExtensionPackageDescriptor0202(manifest CanonicalExtensionManifest0201, buildEpoch int64, manifestSHA, canonicalManifestSHA, checksumsSHA, sbomSHA string, payload ExtensionPackagePayload0202) (ExtensionPackageDescriptor0202, error) {
	material := extensionPackageIdentityMaterial0202{
		Format:                  extensionPackageFormat0202,
		FormatVersion:           extensionPackageFormatVersion0202,
		ExtensionID:             manifest.ID,
		ExtensionVersion:        manifest.Version,
		Publisher:               manifest.Publisher,
		API:                     manifest.API,
		BuildEpoch:              buildEpoch,
		ManifestSHA256:          strings.ToLower(manifestSHA),
		CanonicalManifestSHA256: strings.ToLower(canonicalManifestSHA),
		ChecksumsSHA256:         strings.ToLower(checksumsSHA),
		SBOMSHA256:              strings.ToLower(sbomSHA),
		Payload:                 payload,
	}
	identityBytes, err := json.Marshal(material)
	if err != nil {
		return ExtensionPackageDescriptor0202{}, err
	}
	identityDigest := sha256.Sum256(identityBytes)
	return ExtensionPackageDescriptor0202{
		Format:                  material.Format,
		FormatVersion:           material.FormatVersion,
		ExtensionID:             material.ExtensionID,
		ExtensionVersion:        material.ExtensionVersion,
		Publisher:               material.Publisher,
		API:                     material.API,
		BuildEpoch:              material.BuildEpoch,
		PackageIdentity:         "sha256:" + hex.EncodeToString(identityDigest[:]),
		ManifestSHA256:          material.ManifestSHA256,
		CanonicalManifestSHA256: material.CanonicalManifestSHA256,
		ChecksumsSHA256:         material.ChecksumsSHA256,
		SBOMSHA256:              material.SBOMSHA256,
		Payload:                 material.Payload,
	}, nil
}

func validateExtensionArchivePath0202(name string) error {
	if name == "" || len(name) > 1024 {
		return errors.New("archive path пуст или слишком длинный")
	}
	if strings.ContainsRune(name, '\x00') || strings.Contains(name, "\\") || strings.HasPrefix(name, "/") || path.IsAbs(name) {
		return errors.New("archive path должен быть относительным POSIX path")
	}
	if path.Clean(name) != name || name == "." || name == ".." || strings.HasPrefix(name, "../") || strings.Contains(name, "/../") || strings.HasSuffix(name, "/") {
		return errors.New("archive path содержит traversal/неcanonical компоненты")
	}
	for _, segment := range strings.Split(name, "/") {
		if segment == "" || segment == "." || segment == ".." || len(segment) > 255 {
			return errors.New("archive path содержит некорректный segment")
		}
		if strings.HasSuffix(segment, ".") || strings.HasSuffix(segment, " ") || strings.Contains(segment, ":") {
			return errors.New("archive path несовместим с Windows-safe extraction")
		}
		for _, r := range segment {
			if r < 0x20 {
				return errors.New("archive path содержит control character")
			}
		}
		base := strings.ToUpper(strings.TrimSuffix(segment, path.Ext(segment)))
		if base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" || (len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '1' && base[3] <= '9') {
			return fmt.Errorf("archive path использует зарезервированное Windows-имя %q", segment)
		}
	}
	return nil
}

func analyzeExtensionPackage0202(packagePath string) (*extensionPackageAnalysis0202, error) {
	if strings.ToLower(filepath.Ext(packagePath)) != ".nlext" {
		return nil, errors.New("extension package должен иметь расширение .nlext")
	}
	reader, err := zip.OpenReader(packagePath)
	if err != nil {
		return nil, fmt.Errorf("open .nlext: %w", err)
	}
	analysis := &extensionPackageAnalysis0202{Path: packagePath, Reader: reader, Entries: map[string]*zip.File{}}
	failed := true
	defer func() {
		if failed {
			_ = analysis.Close()
		}
	}()
	if len(reader.File) == 0 || len(reader.File) > extensionPackageMaxFiles0202+5 {
		return nil, fmt.Errorf("некорректное число .nlext entries: %d", len(reader.File))
	}
	caseFolded := map[string]string{}
	var total uint64
	for _, entry := range reader.File {
		if err := validateExtensionArchivePath0202(entry.Name); err != nil {
			return nil, fmt.Errorf("unsafe .nlext entry %q: %w", entry.Name, err)
		}
		fold := strings.ToLower(entry.Name)
		if previous, exists := caseFolded[fold]; exists {
			return nil, fmt.Errorf("duplicate/case-colliding .nlext entries: %q и %q", previous, entry.Name)
		}
		caseFolded[fold] = entry.Name
		if entry.FileInfo().Mode()&os.ModeSymlink != 0 || !entry.FileInfo().Mode().IsRegular() {
			return nil, fmt.Errorf("symlink/special entry запрещён в .nlext: %s", entry.Name)
		}
		perm := entry.FileInfo().Mode().Perm()
		if perm != 0o644 && perm != 0o755 {
			return nil, fmt.Errorf("неканонический file mode %04o для %s", perm, entry.Name)
		}
		if entry.Method != zip.Deflate {
			return nil, fmt.Errorf("неканонический compression method для %s", entry.Name)
		}
		if entry.UncompressedSize64 > uint64(extensionPackageMaxSingleFile0202) {
			return nil, fmt.Errorf("entry %s превышает per-file limit", entry.Name)
		}
		total += entry.UncompressedSize64
		if total > uint64(extensionPackageMaxTotalBytes0202+4*extensionPackageMaxMetadata0202) {
			return nil, errors.New(".nlext превышает uncompressed size limit")
		}
		if entry.UncompressedSize64 > 0 && entry.CompressedSize64 == 0 {
			return nil, fmt.Errorf("подозрительный compression ratio для %s", entry.Name)
		}
		if entry.CompressedSize64 > 0 && entry.UncompressedSize64/entry.CompressedSize64 > extensionPackageMaxCompressionRatio {
			return nil, fmt.Errorf("compression ratio limit exceeded для %s", entry.Name)
		}
		analysis.Entries[entry.Name] = entry
	}
	for _, required := range []string{extensionPackageManifestName0202, extensionPackageChecksumsName0202, extensionPackageSBOMName0202, extensionPackageDescriptorName0202} {
		if _, ok := analysis.Entries[required]; !ok {
			return nil, fmt.Errorf(".nlext не содержит обязательный файл %s", required)
		}
	}
	for name := range analysis.Entries {
		if strings.HasPrefix(name, extensionPackagePayloadPrefix0202) {
			continue
		}
		if _, allowed := extensionPackageReservedRoot0202[name]; !allowed {
			return nil, fmt.Errorf("неожиданный top-level .nlext entry: %s", name)
		}
	}

	manifestBytes, err := readExtensionZipEntry0202(analysis.Entries[extensionPackageManifestName0202], extensionPackageMaxMetadata0202)
	if err != nil {
		return nil, err
	}
	manifest, canonicalDigest, err := decodeCanonicalExtensionManifestBytes0202(manifestBytes)
	if err != nil {
		return nil, err
	}
	expectedManifestBytes, err := canonicalExtensionManifestBytes0202(manifest)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(manifestBytes, expectedManifestBytes) {
		return nil, errors.New("neverlauncher-extension.json внутри .nlext не canonical")
	}
	analysis.Manifest = manifest
	analysis.ManifestBytes = manifestBytes
	analysis.CanonicalDigest = canonicalDigest

	payloadFiles := make([]ExtensionPackageFile0202, 0)
	payloadTotal := int64(0)
	payloadNames := make([]string, 0)
	for name := range analysis.Entries {
		if strings.HasPrefix(name, extensionPackagePayloadPrefix0202) {
			payloadNames = append(payloadNames, name)
		}
	}
	sort.Strings(payloadNames)
	for _, archiveName := range payloadNames {
		entry := analysis.Entries[archiveName]
		digest, size, err := hashExtensionZipEntry0202(entry, extensionPackageMaxSingleFile0202)
		if err != nil {
			return nil, err
		}
		mode := entry.FileInfo().Mode().Perm()
		payloadFiles = append(payloadFiles, ExtensionPackageFile0202{Path: strings.TrimPrefix(archiveName, extensionPackagePayloadPrefix0202), Size: size, SHA256: digest, Mode: fmt.Sprintf("%04o", mode)})
		payloadTotal += size
	}
	payload := ExtensionPackagePayload0202{FileCount: len(payloadFiles), TotalBytes: payloadTotal, Files: payloadFiles}
	if payload.FileCount == 0 {
		return nil, errors.New(".nlext payload пуст")
	}
	if err := ensureExtensionEntrypointsInPackage0202(manifest, payloadFiles); err != nil {
		return nil, err
	}

	checksumsBytes, err := readExtensionZipEntry0202(analysis.Entries[extensionPackageChecksumsName0202], extensionPackageMaxMetadata0202)
	if err != nil {
		return nil, err
	}
	manifestStoredDigest := sha256.Sum256(manifestBytes)
	expectedChecksums := extensionChecksumsBytes0202(hex.EncodeToString(manifestStoredDigest[:]), payloadFiles)
	if !bytes.Equal(checksumsBytes, expectedChecksums) {
		return nil, errors.New("checksums.sha256 не соответствует manifest/payload")
	}
	analysis.ChecksumsBytes = checksumsBytes

	descriptorBytes, err := readExtensionZipEntry0202(analysis.Entries[extensionPackageDescriptorName0202], extensionPackageMaxMetadata0202)
	if err != nil {
		return nil, err
	}
	var descriptor ExtensionPackageDescriptor0202
	if err := decodeStrictJSON0202(descriptorBytes, &descriptor); err != nil {
		return nil, fmt.Errorf("decode neverlauncher-package.json: %w", err)
	}
	if descriptor.Format != extensionPackageFormat0202 || descriptor.FormatVersion != extensionPackageFormatVersion0202 {
		return nil, fmt.Errorf("unsupported .nlext format %q/%q", descriptor.Format, descriptor.FormatVersion)
	}
	if descriptor.BuildEpoch < 315532800 {
		return nil, errors.New("neverlauncher-package.json содержит некорректный buildEpoch")
	}
	buildTime := time.Unix(descriptor.BuildEpoch, 0).UTC()
	for _, entry := range reader.File {
		if !sameZipTimestamp0202(entry.Modified.UTC(), buildTime) {
			return nil, fmt.Errorf("неканонический ZIP timestamp для %s", entry.Name)
		}
	}

	sbomBytes, err := readExtensionZipEntry0202(analysis.Entries[extensionPackageSBOMName0202], extensionPackageMaxMetadata0202)
	if err != nil {
		return nil, err
	}
	if err := validateExtensionSBOM0203(sbomBytes, manifest, canonicalDigest, payload, buildTime); err != nil {
		return nil, err
	}
	analysis.SBOMBytes = sbomBytes

	checksumsDigest := sha256.Sum256(checksumsBytes)
	sbomDigest := sha256.Sum256(sbomBytes)
	expectedDescriptor, err := buildExtensionPackageDescriptor0202(manifest, descriptor.BuildEpoch, hex.EncodeToString(manifestStoredDigest[:]), canonicalDigest, hex.EncodeToString(checksumsDigest[:]), hex.EncodeToString(sbomDigest[:]), payload)
	if err != nil {
		return nil, err
	}
	expectedDescriptorBytes, err := marshalCanonicalPrettyJSON0202(expectedDescriptor)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(descriptorBytes, expectedDescriptorBytes) {
		return nil, errors.New("neverlauncher-package.json/immutable package identity не соответствует содержимому .nlext")
	}
	analysis.Descriptor = descriptor
	analysis.DescriptorBytes = descriptorBytes

	if signatureEntry, ok := analysis.Entries[extensionPackageSignatureName0202]; ok {
		signatureBytes, err := readExtensionZipEntry0202(signatureEntry, extensionPackageMaxMetadata0202)
		if err != nil {
			return nil, err
		}
		var envelope ExtensionPackageSignature0202
		if err := decodeStrictJSON0202(signatureBytes, &envelope); err != nil {
			return nil, fmt.Errorf("decode signature.ed25519: %w", err)
		}
		if envelope.SchemaVersion != "1.0" || envelope.Algorithm != "Ed25519" || envelope.SigningDomain != extensionSigningDomain0202() || envelope.PackageIdentity != descriptor.PackageIdentity {
			return nil, errors.New("signature.ed25519 metadata не соответствует package identity/format")
		}
		sig, err := base64.StdEncoding.DecodeString(envelope.Signature)
		if err != nil || len(sig) != ed25519.SignatureSize {
			return nil, errors.New("signature.ed25519 содержит некорректную Ed25519 signature")
		}
		if !strings.HasPrefix(envelope.KeyFingerprint, "sha256:") || len(envelope.KeyFingerprint) != len("sha256:")+64 {
			return nil, errors.New("signature.ed25519 содержит некорректный keyFingerprint")
		}
		if _, err := hex.DecodeString(strings.TrimPrefix(envelope.KeyFingerprint, "sha256:")); err != nil {
			return nil, errors.New("signature.ed25519 keyFingerprint не является SHA-256 hex")
		}
		expectedSignatureBytes, err := marshalCanonicalPrettyJSON0202(envelope)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(signatureBytes, expectedSignatureBytes) {
			return nil, errors.New("signature.ed25519 не canonical")
		}
		analysis.Signature = &envelope
		analysis.SignatureBytes = signatureBytes
	}
	failed = false
	return analysis, nil
}

func decodeCanonicalExtensionManifestBytes0202(data []byte) (CanonicalExtensionManifest0201, string, error) {
	var manifest CanonicalExtensionManifest0201
	if err := decodeStrictJSON0202(data, &manifest); err != nil {
		return CanonicalExtensionManifest0201{}, "", fmt.Errorf("decode packaged manifest: %w", err)
	}
	normalized, digest, err := normalizeCanonicalExtension0201(manifest)
	return normalized, digest, err
}

func decodeStrictJSON0202(data []byte, out any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return err
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}

func readExtensionZipEntry0202(entry *zip.File, limit int64) ([]byte, error) {
	if entry == nil {
		return nil, errors.New("nil zip entry")
	}
	if entry.UncompressedSize64 > uint64(limit) {
		return nil, fmt.Errorf("metadata entry %s превышает limit", entry.Name)
	}
	reader, err := entry.Open()
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	data, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit || uint64(len(data)) != entry.UncompressedSize64 {
		return nil, fmt.Errorf("metadata entry %s size mismatch/limit exceeded", entry.Name)
	}
	return data, nil
}

func hashExtensionZipEntry0202(entry *zip.File, limit int64) (string, int64, error) {
	if entry.UncompressedSize64 > uint64(limit) {
		return "", 0, fmt.Errorf("entry %s превышает limit", entry.Name)
	}
	reader, err := entry.Open()
	if err != nil {
		return "", 0, err
	}
	defer reader.Close()
	h := sha256.New()
	size, err := io.Copy(h, io.LimitReader(reader, limit+1))
	if err != nil {
		return "", 0, err
	}
	if size > limit || uint64(size) != entry.UncompressedSize64 {
		return "", 0, fmt.Errorf("entry %s size mismatch/limit exceeded", entry.Name)
	}
	return hex.EncodeToString(h.Sum(nil)), size, nil
}

func ensureExtensionEntrypointsInPackage0202(manifest CanonicalExtensionManifest0201, files []ExtensionPackageFile0202) error {
	present := make(map[string]struct{}, len(files))
	for _, file := range files {
		present[file.Path] = struct{}{}
	}
	for _, target := range manifest.Targets {
		if _, ok := present[target.Entrypoint]; !ok {
			return fmt.Errorf("target %s entrypoint %q отсутствует в packaged payload", target.Kind, target.Entrypoint)
		}
	}
	return nil
}

func sameZipTimestamp0202(actual, expected time.Time) bool {
	// ZIP's DOS timestamp has two-second granularity; Go may additionally retain
	// an extended timestamp. Accept the canonical instant within that granularity.
	delta := actual.Unix() - expected.Unix()
	return delta >= -1 && delta <= 1
}

func signExtensionPackage0202(packagePath, outputPath, privateKeyPath string, force bool) (map[string]any, error) {
	analysis, err := analyzeExtensionPackage0202(packagePath)
	if err != nil {
		return nil, err
	}
	defer analysis.Close()
	if analysis.Signature != nil && !force {
		return nil, errors.New(".nlext уже подписан; используйте --force для замены signature")
	}
	privateKey, err := loadEd25519PrivateKey(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("extension signing key: %w", err)
	}
	pub := privateKey.Public().(ed25519.PublicKey)
	pubDigest := sha256.Sum256(pub)
	message := extensionSigningMessage0202(analysis.Descriptor.PackageIdentity)
	envelope := ExtensionPackageSignature0202{
		SchemaVersion:   "1.0",
		Algorithm:       "Ed25519",
		SigningDomain:   extensionSigningDomain0202(),
		PackageIdentity: analysis.Descriptor.PackageIdentity,
		KeyFingerprint:  "sha256:" + hex.EncodeToString(pubDigest[:]),
		Signature:       base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, message)),
	}
	signatureBytes, err := marshalCanonicalPrettyJSON0202(envelope)
	if err != nil {
		return nil, err
	}
	if strings.ToLower(filepath.Ext(outputPath)) != ".nlext" {
		return nil, errors.New("extension package output должен иметь расширение .nlext")
	}
	outputAbs, err := filepath.Abs(filepath.Clean(outputPath))
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(outputAbs), 0o755); err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(outputAbs), ".nlext-sign-*.tmp")
	if err != nil {
		return nil, err
	}
	tmpPath := tmp.Name()
	ok := false
	defer func() {
		_ = tmp.Close()
		if !ok {
			_ = os.Remove(tmpPath)
		}
	}()
	zw := zip.NewWriter(tmp)
	buildTime := time.Unix(analysis.Descriptor.BuildEpoch, 0).UTC()
	canonicalOrder := []string{extensionPackageManifestName0202}
	payloadNames := make([]string, 0)
	for name := range analysis.Entries {
		if strings.HasPrefix(name, extensionPackagePayloadPrefix0202) {
			payloadNames = append(payloadNames, name)
		}
	}
	sort.Strings(payloadNames)
	canonicalOrder = append(canonicalOrder, payloadNames...)
	canonicalOrder = append(canonicalOrder, extensionPackageChecksumsName0202, extensionPackageSBOMName0202, extensionPackageDescriptorName0202)
	for _, name := range canonicalOrder {
		entry := analysis.Entries[name]
		if entry == nil {
			_ = zw.Close()
			return nil, fmt.Errorf("missing package entry during signing: %s", name)
		}
		if err := copyCanonicalZipEntry0202(zw, entry, buildTime); err != nil {
			_ = zw.Close()
			return nil, err
		}
	}
	if err := writeDeterministicZipBytes0202(zw, extensionPackageSignatureName0202, signatureBytes, 0o644, buildTime); err != nil {
		_ = zw.Close()
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	if err := tmp.Sync(); err != nil {
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	// Close the source archive before an in-place replacement. This is required
	// on Windows, where an open ZIP cannot be renamed over.
	if err := analysis.Close(); err != nil {
		return nil, err
	}
	if err := replaceFileAtomically0202(tmpPath, outputAbs, 0o644); err != nil {
		return nil, err
	}
	ok = true

	packageDigest, packageSize, err := hashFile(outputAbs)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"signed":          true,
		"path":            outputPath,
		"extensionId":     analysis.Manifest.ID,
		"version":         analysis.Manifest.Version,
		"packageIdentity": analysis.Descriptor.PackageIdentity,
		"keyFingerprint":  envelope.KeyFingerprint,
		"sha256":          packageDigest,
		"size":            packageSize,
	}, nil
}

func copyCanonicalZipEntry0202(zw *zip.Writer, source *zip.File, modified time.Time) error {
	reader, err := source.Open()
	if err != nil {
		return err
	}
	defer reader.Close()
	header := &zip.FileHeader{Name: source.Name, Method: zip.Deflate}
	header.SetMode(source.FileInfo().Mode().Perm())
	header.SetModTime(modified)
	header.Comment = ""
	header.Extra = nil
	header.NonUTF8 = false
	writer, err := zw.CreateHeader(header)
	if err != nil {
		return err
	}
	written, err := io.Copy(writer, io.LimitReader(reader, int64(source.UncompressedSize64)+1))
	if err != nil {
		return err
	}
	if uint64(written) != source.UncompressedSize64 {
		return fmt.Errorf("entry %s changed during signing copy", source.Name)
	}
	return nil
}

func extensionSigningDomain0202() string {
	return "neverlauncher.extension-package.v1"
}

func extensionSigningMessage0202(identity string) []byte {
	return []byte(extensionSigningDomain0202() + "\n" + identity + "\n")
}

func verifyExtensionPackage0202(packagePath, publicKeyPath string, allowUnsigned bool) (map[string]any, error) {
	analysis, err := analyzeExtensionPackage0202(packagePath)
	if err != nil {
		return nil, err
	}
	defer analysis.Close()
	status := "integrity-verified"
	keyFingerprint := ""
	if analysis.Signature == nil {
		if !allowUnsigned {
			return nil, errors.New(".nlext unsigned: signature.ed25519 обязателен; для integrity-only проверки используйте --allow-unsigned")
		}
	} else {
		if strings.TrimSpace(publicKeyPath) == "" {
			return nil, errors.New("signed .nlext verification требует --public-key или NEVERLAUNCHER_EXTENSION_SIGNING_PUBLIC_KEY_FILE")
		}
		publicKey, err := loadEd25519PublicKey(publicKeyPath)
		if err != nil {
			return nil, fmt.Errorf("extension verification key: %w", err)
		}
		pubDigest := sha256.Sum256(publicKey)
		keyFingerprint = "sha256:" + hex.EncodeToString(pubDigest[:])
		if !strings.EqualFold(keyFingerprint, analysis.Signature.KeyFingerprint) {
			return nil, fmt.Errorf("signature key mismatch: package=%s trusted=%s", analysis.Signature.KeyFingerprint, keyFingerprint)
		}
		sig, _ := base64.StdEncoding.DecodeString(analysis.Signature.Signature)
		if !ed25519.Verify(publicKey, extensionSigningMessage0202(analysis.Descriptor.PackageIdentity), sig) {
			return nil, errors.New("Ed25519 verification failed для .nlext package identity")
		}
		status = "signature-verified"
	}
	packageDigest, packageSize, err := hashFile(packagePath)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"verified":        true,
		"status":          status,
		"path":            packagePath,
		"extensionId":     analysis.Manifest.ID,
		"version":         analysis.Manifest.Version,
		"publisher":       analysis.Manifest.Publisher,
		"packageIdentity": analysis.Descriptor.PackageIdentity,
		"signed":          analysis.Signature != nil,
		"keyFingerprint":  keyFingerprint,
		"sha256":          packageDigest,
		"size":            packageSize,
		"payloadFiles":    analysis.Descriptor.Payload.FileCount,
		"payloadBytes":    analysis.Descriptor.Payload.TotalBytes,
	}, nil
}

func inspectExtensionPackage0202(packagePath string, includeFiles bool) (map[string]any, error) {
	analysis, err := analyzeExtensionPackage0202(packagePath)
	if err != nil {
		return nil, err
	}
	defer analysis.Close()
	packageDigest, packageSize, err := hashFile(packagePath)
	if err != nil {
		return nil, err
	}
	result := map[string]any{
		"valid":           true,
		"path":            packagePath,
		"format":          analysis.Descriptor.Format,
		"formatVersion":   analysis.Descriptor.FormatVersion,
		"extensionId":     analysis.Manifest.ID,
		"name":            analysis.Manifest.Name,
		"version":         analysis.Manifest.Version,
		"publisher":       analysis.Manifest.Publisher,
		"api":             analysis.Manifest.API,
		"targets":         analysis.Manifest.Targets,
		"packageIdentity": analysis.Descriptor.PackageIdentity,
		"manifestSha256":  analysis.Descriptor.ManifestSHA256,
		"payloadFiles":    analysis.Descriptor.Payload.FileCount,
		"payloadBytes":    analysis.Descriptor.Payload.TotalBytes,
		"signed":          analysis.Signature != nil,
		"sha256":          packageDigest,
		"size":            packageSize,
	}
	if analysis.Signature != nil {
		result["signature"] = map[string]any{"algorithm": analysis.Signature.Algorithm, "keyFingerprint": analysis.Signature.KeyFingerprint, "trust": "not-evaluated"}
	}
	if includeFiles {
		result["files"] = analysis.Descriptor.Payload.Files
	}
	return result, nil
}

func replaceFileAtomically0202(tempPath, destination string, mode os.FileMode) error {
	if err := os.Chmod(tempPath, mode); err != nil {
		return err
	}
	if err := os.Rename(tempPath, destination); err == nil {
		return nil
	}
	// Windows cannot replace an existing destination atomically with os.Rename.
	backup := destination + ".replace-old"
	_ = os.Remove(backup)
	if _, err := os.Stat(destination); err == nil {
		if err := os.Rename(destination, backup); err != nil {
			return err
		}
	}
	if err := os.Rename(tempPath, destination); err != nil {
		_ = os.Rename(backup, destination)
		return err
	}
	_ = os.Remove(backup)
	return nil
}
