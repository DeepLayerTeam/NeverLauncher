package extensionpackage

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
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/extensioncontract"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

const (
	formatName0203        = extensioncontract.PackageFormatName
	formatVersion0203     = extensioncontract.PackageFormatVersion
	manifestName0203      = "neverlauncher-extension.json"
	checksumsName0203     = "checksums.sha256"
	sbomName0203          = "SBOM.spdx.json"
	descriptorName0203    = "neverlauncher-package.json"
	signatureName0203     = "signature.ed25519"
	payloadPrefix0203     = "payload/"
	maxFiles0203          = 10000
	maxSingleFile0203     = int64(512 << 20)
	maxTotalBytes0203     = int64(2 << 30)
	maxMetadata0203       = int64(8 << 20)
	maxCompressionRatio03 = uint64(10000)
)

var reservedRoot0203 = map[string]struct{}{manifestName0203: {}, checksumsName0203: {}, sbomName0203: {}, descriptorName0203: {}, signatureName0203: {}}

type PackageFile struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	Mode   string `json:"mode"`
}

type PackagePayload struct {
	FileCount  int           `json:"fileCount"`
	TotalBytes int64         `json:"totalBytes"`
	Files      []PackageFile `json:"files"`
}

type Descriptor struct {
	Format                  string         `json:"format"`
	FormatVersion           string         `json:"formatVersion"`
	ExtensionID             string         `json:"extensionId"`
	ExtensionVersion        string         `json:"extensionVersion"`
	Publisher               string         `json:"publisher"`
	API                     string         `json:"api"`
	BuildEpoch              int64          `json:"buildEpoch"`
	PackageIdentity         string         `json:"packageIdentity"`
	ManifestSHA256          string         `json:"manifestSha256"`
	CanonicalManifestSHA256 string         `json:"canonicalManifestSha256"`
	ChecksumsSHA256         string         `json:"checksumsSha256"`
	SBOMSHA256              string         `json:"sbomSha256"`
	Payload                 PackagePayload `json:"payload"`
}

type identityMaterial0203 struct {
	Format                  string         `json:"format"`
	FormatVersion           string         `json:"formatVersion"`
	ExtensionID             string         `json:"extensionId"`
	ExtensionVersion        string         `json:"extensionVersion"`
	Publisher               string         `json:"publisher"`
	API                     string         `json:"api"`
	BuildEpoch              int64          `json:"buildEpoch"`
	ManifestSHA256          string         `json:"manifestSha256"`
	CanonicalManifestSHA256 string         `json:"canonicalManifestSha256"`
	ChecksumsSHA256         string         `json:"checksumsSha256"`
	SBOMSHA256              string         `json:"sbomSha256"`
	Payload                 PackagePayload `json:"payload"`
}

type Signature struct {
	SchemaVersion   string `json:"schemaVersion"`
	Algorithm       string `json:"algorithm"`
	SigningDomain   string `json:"signingDomain"`
	PackageIdentity string `json:"packageIdentity"`
	KeyFingerprint  string `json:"keyFingerprint"`
	Signature       string `json:"signature"`
}

type VerifiedPackage struct {
	Manifest        model.ExtensionManifest
	Descriptor      Descriptor
	Signature       Signature
	SHA256          string
	Size            int64
	PackageIdentity string
	KeyFingerprint  string
}

type analysis0203 struct {
	reader          *zip.ReadCloser
	entries         map[string]*zip.File
	manifest        model.ExtensionManifest
	manifestBytes   []byte
	canonicalDigest string
	descriptor      Descriptor
	signature       *Signature
}

func (a *analysis0203) close() error {
	if a == nil || a.reader == nil {
		return nil
	}
	return a.reader.Close()
}

func signingDomain0203() string { return "neverlauncher.extension-package.v1" }
func signingMessage0203(identity string) []byte {
	return []byte(signingDomain0203() + "\n" + identity + "\n")
}

func canonicalJSON0203(value any) ([]byte, error) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func strictJSON0203(data []byte, out any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("след JSON value")
		}
		return err
	}
	return nil
}

func validateArchivePath0203(name string) error {
	if name == "" || len(name) > 1024 {
		return errors.New("путь в архиве является пустой или слишком long")
	}
	if strings.ContainsRune(name, '\x00') || strings.Contains(name, "\\") || strings.HasPrefix(name, "/") || path.IsAbs(name) {
		return errors.New("путь в архиве должен быть relative POSIX путь")
	}
	if path.Clean(name) != name || name == "." || name == ".." || strings.HasPrefix(name, "../") || strings.Contains(name, "/../") || strings.HasSuffix(name, "/") {
		return errors.New("путь в архиве содержит traversal/non-canonical компонент")
	}
	for _, segment := range strings.Split(name, "/") {
		if segment == "" || segment == "." || segment == ".." || len(segment) > 255 {
			return errors.New("путь в архиве содержит недопустимый segment")
		}
		if strings.HasSuffix(segment, ".") || strings.HasSuffix(segment, " ") || strings.Contains(segment, ":") {
			return errors.New("путь в архиве является не Windows-безопасный")
		}
		for _, r := range segment {
			if r < 0x20 {
				return errors.New("путь в архиве содержит управление character")
			}
		}
		base := strings.ToUpper(strings.TrimSuffix(segment, path.Ext(segment)))
		if base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" || (len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '1' && base[3] <= '9') {
			return fmt.Errorf("путь в архиве использует reserved Windows имя %q", segment)
		}
	}
	return nil
}

func readEntry0203(entry *zip.File, limit int64) ([]byte, error) {
	if entry == nil {
		return nil, errors.New("отсутствующий ZIP запись")
	}
	if entry.UncompressedSize64 > uint64(limit) {
		return nil, fmt.Errorf("запись %s exceeds размер ограничение", entry.Name)
	}
	r, err := entry.Open()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit || uint64(len(data)) != entry.UncompressedSize64 {
		return nil, fmt.Errorf("запись %s размер несоответствие", entry.Name)
	}
	return data, nil
}

func hashEntry0203(entry *zip.File, limit int64) (string, int64, error) {
	r, err := entry.Open()
	if err != nil {
		return "", 0, err
	}
	defer r.Close()
	h := sha256.New()
	written, err := io.Copy(h, io.LimitReader(r, limit+1))
	if err != nil {
		return "", written, err
	}
	if written > limit || uint64(written) != entry.UncompressedSize64 {
		return "", written, fmt.Errorf("запись %s exceeds размер ограничение или изменён размер", entry.Name)
	}
	return hex.EncodeToString(h.Sum(nil)), written, nil
}

func checksumBytes0203(manifestSHA string, files []PackageFile) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "%s  %s\n", strings.ToLower(manifestSHA), manifestName0203)
	for _, file := range files {
		fmt.Fprintf(&b, "%s  %s%s\n", strings.ToLower(file.SHA256), payloadPrefix0203, file.Path)
	}
	return []byte(b.String())
}

type spdxChecksum0203 struct {
	Algorithm     string `json:"algorithm"`
	ChecksumValue string `json:"checksumValue"`
}
type spdxFile0203 struct {
	SPDXID    string             `json:"SPDXID"`
	FileName  string             `json:"fileName"`
	Checksums []spdxChecksum0203 `json:"checksums"`
}
type spdxPackage0203 struct {
	SPDXID           string `json:"SPDXID"`
	Name             string `json:"name"`
	VersionInfo      string `json:"versionInfo"`
	DownloadLocation string `json:"downloadLocation"`
	FilesAnalyzed    bool   `json:"filesAnalyzed"`
	LicenseConcluded string `json:"licenseConcluded"`
	LicenseDeclared  string `json:"licenseDeclared"`
}
type spdxRelationship0203 struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
}
type spdxCreationInfo0203 struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}
type spdxDocument0203 struct {
	SPDXVersion       string                 `json:"spdxVersion"`
	DataLicense       string                 `json:"dataLicense"`
	SPDXID            string                 `json:"SPDXID"`
	Name              string                 `json:"name"`
	DocumentNamespace string                 `json:"documentNamespace"`
	CreationInfo      spdxCreationInfo0203   `json:"creationInfo"`
	Packages          []spdxPackage0203      `json:"packages"`
	Files             []spdxFile0203         `json:"files"`
	Relationships     []spdxRelationship0203 `json:"relationships"`
}

func validateSBOM0203(data []byte, manifest model.ExtensionManifest, canonicalDigest string, payload PackagePayload, buildTime time.Time) error {
	var doc spdxDocument0203
	if err := strictJSON0203(data, &doc); err != nil {
		return fmt.Errorf("decode SBOM.spdx.JSON: %w", err)
	}
	if doc.SPDXVersion != "SPDX-2.3" || doc.DataLicense != "CC0-1.0" || doc.SPDXID != "SPDXRef-DOCUMENT" || doc.Name != manifest.ID+" "+manifest.Version || doc.DocumentNamespace != "https://neverlauncher.local/spdx/extension/"+manifest.ID+"/"+manifest.Version+"/"+canonicalDigest {
		return errors.New("SBOM.spdx.JSON документ метаданные делает не соответствовать пакет")
	}
	if doc.CreationInfo.Created != buildTime.Format(time.RFC3339) || len(doc.CreationInfo.Creators) != 1 || !strings.HasPrefix(doc.CreationInfo.Creators[0], "Tool: NeverLauncher CLI ") {
		return errors.New("SBOM.spdx.JSON creationInfo является недопустимый")
	}
	pkgID := "SPDXRef-Package-Extension"
	if len(doc.Packages) != 1 {
		return errors.New("SBOM.spdx.JSON должен описывать точно один пакет расширения")
	}
	pkg := doc.Packages[0]
	if pkg.SPDXID != pkgID || pkg.Name != manifest.Name || pkg.VersionInfo != manifest.Version || pkg.DownloadLocation != "NOASSERTION" || !pkg.FilesAnalyzed || pkg.LicenseConcluded != "NOASSERTION" || pkg.LicenseDeclared != "NOASSERTION" {
		return errors.New("SBOM.spdx.JSON пакет метаданные делает не соответствовать манифест")
	}
	if len(doc.Files) != len(payload.Files) || len(doc.Relationships) != len(payload.Files)+1 {
		return errors.New("SBOM.spdx.JSON file/relationship счётчик делает не соответствовать полезная нагрузка")
	}
	if doc.Relationships[0] != (spdxRelationship0203{SPDXElementID: "SPDXRef-DOCUMENT", RelationshipType: "DESCRIBES", RelatedSPDXElement: pkgID}) {
		return errors.New("SBOM.spdx.JSON DESCRIBES relationship является недопустимый")
	}
	for i, file := range payload.Files {
		pathDigest := sha256.Sum256([]byte(file.Path))
		fileID := "SPDXRef-File-" + hex.EncodeToString(pathDigest[:8])
		expectedFile := spdxFile0203{SPDXID: fileID, FileName: "./" + payloadPrefix0203 + file.Path, Checksums: []spdxChecksum0203{{Algorithm: "SHA256", ChecksumValue: file.SHA256}}}
		actual := doc.Files[i]
		if actual.SPDXID != expectedFile.SPDXID || actual.FileName != expectedFile.FileName || len(actual.Checksums) != 1 || actual.Checksums[0] != expectedFile.Checksums[0] {
			return fmt.Errorf("SBOM.spdx.JSON файл запись %d делает не соответствовать полезная нагрузка", i)
		}
		expectedRel := spdxRelationship0203{SPDXElementID: pkgID, RelationshipType: "CONTAINS", RelatedSPDXElement: fileID}
		if doc.Relationships[i+1] != expectedRel {
			return fmt.Errorf("SBOM.spdx.JSON relationship %d делает не соответствовать полезная нагрузка", i+1)
		}
	}
	return nil
}

func buildDescriptor0203(manifest model.ExtensionManifest, buildEpoch int64, manifestSHA, canonicalSHA, checksumsSHA, sbomSHA string, payload PackagePayload) (Descriptor, error) {
	material := identityMaterial0203{Format: formatName0203, FormatVersion: formatVersion0203, ExtensionID: manifest.ID, ExtensionVersion: manifest.Version, Publisher: manifest.Publisher, API: manifest.API, BuildEpoch: buildEpoch, ManifestSHA256: strings.ToLower(manifestSHA), CanonicalManifestSHA256: strings.ToLower(canonicalSHA), ChecksumsSHA256: strings.ToLower(checksumsSHA), SBOMSHA256: strings.ToLower(sbomSHA), Payload: payload}
	identityBytes, err := json.Marshal(material)
	if err != nil {
		return Descriptor{}, err
	}
	digest := sha256.Sum256(identityBytes)
	return Descriptor{Format: material.Format, FormatVersion: material.FormatVersion, ExtensionID: material.ExtensionID, ExtensionVersion: material.ExtensionVersion, Publisher: material.Publisher, API: material.API, BuildEpoch: material.BuildEpoch, PackageIdentity: "sha256:" + hex.EncodeToString(digest[:]), ManifestSHA256: material.ManifestSHA256, CanonicalManifestSHA256: material.CanonicalManifestSHA256, ChecksumsSHA256: material.ChecksumsSHA256, SBOMSHA256: material.SBOMSHA256, Payload: material.Payload}, nil
}

func sameZipTimestamp0203(actual, expected time.Time) bool {
	delta := actual.Unix() - expected.Unix()
	return delta >= -1 && delta <= 1
}

func analyze0203(packagePath string) (*analysis0203, error) {
	reader, err := zip.OpenReader(packagePath)
	if err != nil {
		return nil, fmt.Errorf("открытый.nlext: %w", err)
	}
	a := &analysis0203{reader: reader, entries: map[string]*zip.File{}}
	failed := true
	defer func() {
		if failed {
			_ = a.close()
		}
	}()
	if len(reader.File) == 0 || len(reader.File) > maxFiles0203+5 {
		return nil, fmt.Errorf("недопустимый.nlext запись счётчик: %d", len(reader.File))
	}
	caseFolded := map[string]string{}
	var total uint64
	for _, entry := range reader.File {
		if err := validateArchivePath0203(entry.Name); err != nil {
			return nil, fmt.Errorf("unsafe.nlext запись %q: %w", entry.Name, err)
		}
		fold := strings.ToLower(entry.Name)
		if previous, exists := caseFolded[fold]; exists {
			return nil, fmt.Errorf("duplicate/case-colliding.nlext записи: %q и %q", previous, entry.Name)
		}
		caseFolded[fold] = entry.Name
		if entry.FileInfo().Mode()&os.ModeSymlink != 0 || !entry.FileInfo().Mode().IsRegular() {
			return nil, fmt.Errorf("symlink/special запись является forbidden в.nlext: %s", entry.Name)
		}
		perm := entry.FileInfo().Mode().Perm()
		if perm != 0o644 && perm != 0o755 {
			return nil, fmt.Errorf("non-канонический файл режим %04o для %s", perm, entry.Name)
		}
		if entry.Method != zip.Deflate {
			return nil, fmt.Errorf("non-канонический compression метод для %s", entry.Name)
		}
		if entry.UncompressedSize64 > uint64(maxSingleFile0203) {
			return nil, fmt.Errorf("запись %s exceeds на-файл ограничение", entry.Name)
		}
		total += entry.UncompressedSize64
		if total > uint64(maxTotalBytes0203+4*maxMetadata0203) {
			return nil, errors.New(".nlext exceeds uncompressed размер ограничение")
		}
		if entry.UncompressedSize64 > 0 && entry.CompressedSize64 == 0 {
			return nil, fmt.Errorf("suspicious compression ratio для %s", entry.Name)
		}
		if entry.CompressedSize64 > 0 && entry.UncompressedSize64/entry.CompressedSize64 > maxCompressionRatio03 {
			return nil, fmt.Errorf("compression ratio ограничение exceeded для %s", entry.Name)
		}
		a.entries[entry.Name] = entry
	}
	for _, required := range []string{manifestName0203, checksumsName0203, sbomName0203, descriptorName0203, signatureName0203} {
		if _, ok := a.entries[required]; !ok {
			return nil, fmt.Errorf(".nlext делает не contain обязательный подписанный-реестр файл %s", required)
		}
	}
	for name := range a.entries {
		if strings.HasPrefix(name, payloadPrefix0203) {
			continue
		}
		if _, allowed := reservedRoot0203[name]; !allowed {
			return nil, fmt.Errorf("unexpected top-уровень.nlext запись: %s", name)
		}
	}
	manifestBytes, err := readEntry0203(a.entries[manifestName0203], maxMetadata0203)
	if err != nil {
		return nil, err
	}
	var manifest model.ExtensionManifest
	if err := strictJSON0203(manifestBytes, &manifest); err != nil {
		return nil, fmt.Errorf("decode пакет манифест: %w", err)
	}
	normalized, canonicalDigest, err := repository.NormalizeExtensionManifest(manifest)
	if err != nil {
		return nil, err
	}
	expectedManifestBytes, err := canonicalJSON0203(normalized)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(manifestBytes, expectedManifestBytes) {
		return nil, errors.New("neverlauncher-расширение.JSON внутри.nlext является не канонический")
	}
	a.manifest, a.manifestBytes, a.canonicalDigest = normalized, manifestBytes, canonicalDigest
	payloadFiles := make([]PackageFile, 0)
	payloadNames := make([]string, 0)
	var payloadTotal int64
	for name := range a.entries {
		if strings.HasPrefix(name, payloadPrefix0203) {
			payloadNames = append(payloadNames, name)
		}
	}
	sort.Strings(payloadNames)
	for _, archiveName := range payloadNames {
		entry := a.entries[archiveName]
		digest, size, err := hashEntry0203(entry, maxSingleFile0203)
		if err != nil {
			return nil, err
		}
		payloadFiles = append(payloadFiles, PackageFile{Path: strings.TrimPrefix(archiveName, payloadPrefix0203), Size: size, SHA256: digest, Mode: fmt.Sprintf("%04o", entry.FileInfo().Mode().Perm())})
		payloadTotal += size
	}
	payload := PackagePayload{FileCount: len(payloadFiles), TotalBytes: payloadTotal, Files: payloadFiles}
	if payload.FileCount == 0 {
		return nil, errors.New(".nlext полезная нагрузка является пустой")
	}
	for _, target := range normalized.Targets {
		found := false
		for _, file := range payloadFiles {
			if file.Path == target.Entrypoint {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("цель %s entrypoint %s является отсутствующий из полезная нагрузка", target.Kind, target.Entrypoint)
		}
	}
	checksumsBytes, err := readEntry0203(a.entries[checksumsName0203], maxMetadata0203)
	if err != nil {
		return nil, err
	}
	manifestStoredDigest := sha256.Sum256(manifestBytes)
	if !bytes.Equal(checksumsBytes, checksumBytes0203(hex.EncodeToString(manifestStoredDigest[:]), payloadFiles)) {
		return nil, errors.New("контрольные суммы.sha256 делает не соответствовать manifest/payload")
	}
	descriptorBytes, err := readEntry0203(a.entries[descriptorName0203], maxMetadata0203)
	if err != nil {
		return nil, err
	}
	var descriptor Descriptor
	if err := strictJSON0203(descriptorBytes, &descriptor); err != nil {
		return nil, fmt.Errorf("decode neverlauncher-пакет.JSON: %w", err)
	}
	if descriptor.Format != formatName0203 || descriptor.FormatVersion != formatVersion0203 || descriptor.BuildEpoch < 315532800 {
		return nil, errors.New("unsupported/invalid.nlext пакет дескриптор")
	}
	buildTime := time.Unix(descriptor.BuildEpoch, 0).UTC()
	for _, entry := range reader.File {
		if !sameZipTimestamp0203(entry.Modified.UTC(), buildTime) {
			return nil, fmt.Errorf("non-канонический ZIP метка времени для %s", entry.Name)
		}
	}
	sbomBytes, err := readEntry0203(a.entries[sbomName0203], maxMetadata0203)
	if err != nil {
		return nil, err
	}
	if err := validateSBOM0203(sbomBytes, normalized, canonicalDigest, payload, buildTime); err != nil {
		return nil, err
	}
	checksumsDigest, sbomDigest := sha256.Sum256(checksumsBytes), sha256.Sum256(sbomBytes)
	expectedDescriptor, err := buildDescriptor0203(normalized, descriptor.BuildEpoch, hex.EncodeToString(manifestStoredDigest[:]), canonicalDigest, hex.EncodeToString(checksumsDigest[:]), hex.EncodeToString(sbomDigest[:]), payload)
	if err != nil {
		return nil, err
	}
	expectedDescriptorBytes, err := canonicalJSON0203(expectedDescriptor)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(descriptorBytes, expectedDescriptorBytes) {
		return nil, errors.New("neverlauncher-package.json/package идентичность делает не соответствовать.nlext content")
	}
	a.descriptor = descriptor
	signatureBytes, err := readEntry0203(a.entries[signatureName0203], maxMetadata0203)
	if err != nil {
		return nil, err
	}
	var signature Signature
	if err := strictJSON0203(signatureBytes, &signature); err != nil {
		return nil, fmt.Errorf("decode подпись.ed25519: %w", err)
	}
	if signature.SchemaVersion != "1.0" || signature.Algorithm != "Ed25519" || signature.SigningDomain != signingDomain0203() || signature.PackageIdentity != descriptor.PackageIdentity {
		return nil, errors.New("подпись.ed25519 метаданные делает не соответствовать пакет identity/format")
	}
	sig, err := base64.StdEncoding.DecodeString(signature.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, errors.New("подпись.ed25519 содержит недопустимый Ed25519 подпись")
	}
	if !strings.HasPrefix(signature.KeyFingerprint, "sha256:") || len(signature.KeyFingerprint) != len("sha256:")+64 {
		return nil, errors.New("подпись.ed25519 содержит недопустимый keyFingerprint")
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(signature.KeyFingerprint, "sha256:")); err != nil {
		return nil, errors.New("подпись.ed25519 keyFingerprint является не SHA-256 hex")
	}
	expectedSignatureBytes, err := canonicalJSON0203(signature)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(signatureBytes, expectedSignatureBytes) {
		return nil, errors.New("подпись.ed25519 является не канонический")
	}
	a.signature = &signature
	failed = false
	return a, nil
}

// VerifyFile проверяет полный.nlext целостность и его Ed25519 подпись против
// точный доверенный сырой открытый ключ регистрировать для издатель.
func VerifyFile(packagePath string, publicKey ed25519.PublicKey) (VerifiedPackage, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return VerifiedPackage{}, errors.New("доверенный Ed25519 открытый ключ должен быть 32 байты")
	}
	a, err := analyze0203(packagePath)
	if err != nil {
		return VerifiedPackage{}, err
	}
	defer a.close()
	pubDigest := sha256.Sum256(publicKey)
	fingerprint := "sha256:" + hex.EncodeToString(pubDigest[:])
	if a.signature == nil || !strings.EqualFold(fingerprint, a.signature.KeyFingerprint) {
		return VerifiedPackage{}, fmt.Errorf("подпись ключ несоответствие: пакет=%s доверенный=%s", a.signature.KeyFingerprint, fingerprint)
	}
	sig, _ := base64.StdEncoding.DecodeString(a.signature.Signature)
	if !ed25519.Verify(publicKey, signingMessage0203(a.descriptor.PackageIdentity), sig) {
		return VerifiedPackage{}, errors.New("Ed25519 проверка ошибка для.nlext пакет идентичность")
	}
	file, err := os.Open(packagePath)
	if err != nil {
		return VerifiedPackage{}, err
	}
	defer file.Close()
	h := sha256.New()
	size, err := io.Copy(h, file)
	if err != nil {
		return VerifiedPackage{}, err
	}
	return VerifiedPackage{Manifest: a.manifest, Descriptor: a.descriptor, Signature: *a.signature, SHA256: hex.EncodeToString(h.Sum(nil)), Size: size, PackageIdentity: a.descriptor.PackageIdentity, KeyFingerprint: fingerprint}, nil
}

// InspectSignedFile валидирует пакет structure/identity и возвращает подпись
// метаданные без making доверие решение. Реестр публикация использует этот к select
// точный издатель ключ и затем вызов VerifyFile с тот доверенный ключ.
func InspectSignedFile(packagePath string) (VerifiedPackage, error) {
	a, err := analyze0203(packagePath)
	if err != nil {
		return VerifiedPackage{}, err
	}
	defer a.close()
	file, err := os.Open(packagePath)
	if err != nil {
		return VerifiedPackage{}, err
	}
	defer file.Close()
	h := sha256.New()
	size, err := io.Copy(h, file)
	if err != nil {
		return VerifiedPackage{}, err
	}
	return VerifiedPackage{Manifest: a.manifest, Descriptor: a.descriptor, Signature: *a.signature, SHA256: hex.EncodeToString(h.Sum(nil)), Size: size, PackageIdentity: a.descriptor.PackageIdentity, KeyFingerprint: a.signature.KeyFingerprint}, nil
}

// ExtractPayloadFile re-валидирует канонический.nlext structure и extracts
// только полезная нагрузка/ записи в пустой назначение каталог. Это refuses к
// extract когда packageIdentity делает не соответствовать ожидаемый неизменяемый идентичность.
// Пути были уже отклонён для traversal/symlink/case-collision через analyze0203;
// этот routine additionally создаёт каждый вывод файл с O_EXCL так 
// unexpected pre-существующий путь не может быть overwritten.
func ExtractPayloadFile(packagePath, destination, expectedPackageIdentity string) (model.ExtensionManifest, error) {
	a, err := analyze0203(packagePath)
	if err != nil {
		return model.ExtensionManifest{}, err
	}
	defer a.close()
	expectedPackageIdentity = strings.ToLower(strings.TrimSpace(expectedPackageIdentity))
	if expectedPackageIdentity == "" || a.descriptor.PackageIdentity != expectedPackageIdentity {
		return model.ExtensionManifest{}, errors.New(".nlext пакет идентичность делает не соответствовать ожидаемый неизменяемый идентичность")
	}
	if info, err := os.Lstat(destination); err == nil {
		if !info.IsDir() {
			return model.ExtensionManifest{}, errors.New("расширение подготовка назначение существует и является не каталог")
		}
		entries, err := os.ReadDir(destination)
		if err != nil {
			return model.ExtensionManifest{}, err
		}
		if len(entries) != 0 {
			return model.ExtensionManifest{}, errors.New("расширение подготовка назначение должен быть пустой")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return model.ExtensionManifest{}, err
	} else if err := os.MkdirAll(destination, 0o750); err != nil {
		return model.ExtensionManifest{}, err
	}
	rootAbs, err := filepath.Abs(destination)
	if err != nil {
		return model.ExtensionManifest{}, err
	}
	payloadNames := make([]string, 0)
	for name := range a.entries {
		if strings.HasPrefix(name, payloadPrefix0203) {
			payloadNames = append(payloadNames, name)
		}
	}
	sort.Strings(payloadNames)
	for _, archiveName := range payloadNames {
		entry := a.entries[archiveName]
		rel := strings.TrimPrefix(archiveName, payloadPrefix0203)
		outPath := filepath.Join(destination, filepath.FromSlash(rel))
		outAbs, err := filepath.Abs(outPath)
		if err != nil {
			return model.ExtensionManifest{}, err
		}
		if outAbs == rootAbs || !strings.HasPrefix(outAbs, rootAbs+string(os.PathSeparator)) {
			return model.ExtensionManifest{}, errors.New("расширение полезная нагрузка escaped подготовка корень")
		}
		if err := os.MkdirAll(filepath.Dir(outAbs), 0o750); err != nil {
			return model.ExtensionManifest{}, err
		}
		reader, err := entry.Open()
		if err != nil {
			return model.ExtensionManifest{}, err
		}
		mode := entry.FileInfo().Mode().Perm()
		file, err := os.OpenFile(outAbs, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
		if err != nil {
			reader.Close()
			return model.ExtensionManifest{}, err
		}
		h := sha256.New()
		written, copyErr := io.Copy(io.MultiWriter(file, h), io.LimitReader(reader, maxSingleFile0203+1))
		closeReadErr := reader.Close()
		syncErr := file.Sync()
		closeWriteErr := file.Close()
		if copyErr != nil {
			return model.ExtensionManifest{}, copyErr
		}
		if closeReadErr != nil || syncErr != nil || closeWriteErr != nil {
			return model.ExtensionManifest{}, errors.New("ошибка к долговременно extract расширение полезная нагрузка")
		}
		if written != int64(entry.UncompressedSize64) || written > maxSingleFile0203 {
			return model.ExtensionManifest{}, fmt.Errorf("extracted полезная нагрузка размер несоответствие для %s", rel)
		}
		expected := ""
		for _, f := range a.descriptor.Payload.Files {
			if f.Path == rel {
				expected = f.SHA256
				break
			}
		}
		if expected == "" || hex.EncodeToString(h.Sum(nil)) != expected {
			return model.ExtensionManifest{}, fmt.Errorf("extracted полезная нагрузка хеш несоответствие для %s", rel)
		}
	}
	manifestBytes, err := canonicalJSON0203(a.manifest)
	if err != nil {
		return model.ExtensionManifest{}, err
	}
	metadata := filepath.Join(destination, manifestName0203)
	if err := os.WriteFile(metadata, manifestBytes, 0o640); err != nil {
		return model.ExtensionManifest{}, err
	}
	return a.manifest, nil
}
