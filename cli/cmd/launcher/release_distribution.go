package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Шесть окончательных файлов установщиков, а не промежуточные результаты. Эта проверка дополняет
// независимое подписанное подтверждение нативного исполнения и GA-проверку подписи ОС.
type distributionTarget04511 struct{ target, packageFile string }

func distributionRequired04511(ver string) bool {
	v, ok := parseVersionTriple0158(ver)
	return ok && compareVersionTriple0158(v, [3]int{0, 45, 11}) >= 0
}
func distributionTargets04511(ver string) []distributionTarget04511 {
	return []distributionTarget04511{
		{"windows-x64", "launcher-desktop-" + ver + "-windows-x64.zip"},
		{"windows-arm64", "launcher-desktop-" + ver + "-windows-arm64.zip"},
		{"linux-x64", "launcher-linux-x64-" + ver + ".tar.gz"},
		{"linux-arm64", "launcher-linux-arm64-" + ver + ".tar.gz"},
		{"darwin-x64", "launcher-desktop-" + ver + "-macos-x64.zip"},
		{"darwin-arm64", "launcher-desktop-" + ver + "-macos-arm64.zip"},
	}
}
func distributionSPDXID04511(target string) string { return "SPDXRef-Distribution-" + target }
func distributionHash04511(dir, name string) (string, error) {
	info, err := os.Lstat(filepath.Join(dir, name))
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 {
		return "", fmt.Errorf("not a regular, nonempty package: %s", name)
	}
	digest, _, err := hashFile(filepath.Join(dir, name))
	return digest, err
}

// Привязывайте хеши фактически подготовленных и подписанных платформой установщиков к
// существующему SPDX-документу зависимостей. Одних имён файлов или заявленных целей
// недостаточно для аттестации полученных байтов.
func bindDistributionSBOM04511(document map[string]any, dir, ver string) error {
	if !distributionRequired04511(ver) {
		return nil
	}
	packages, ok := document["packages"].([]sbomPackage)
	if !ok {
		return errors.New("Отсутствует: SPDX пакеты")
	}
	relationships, ok := document["relationships"].([]sbomRelationship)
	if !ok {
		return errors.New("SPDX relationships missing")
	}
	for _, t := range distributionTargets04511(ver) {
		h, err := distributionHash04511(dir, t.packageFile)
		if err != nil {
			return fmt.Errorf("signed distribution %s: %w", t.target, err)
		}
		packages = append(packages, sbomPackage{
			SPDXID: distributionSPDXID04511(t.target), Name: t.packageFile, VersionInfo: ver,
			DownloadLocation: "NOASSERTION", FilesAnalyzed: false, LicenseConcluded: "NOASSERTION", LicenseDeclared: "NOASSERTION",
			PrimaryPackagePurpose: "APPLICATION", Checksums: []sbomChecksum04511{{Algorithm: "SHA256", ChecksumValue: h}},
		})
		relationships = append(relationships, sbomRelationship{SPDXElementID: "SPDXRef-DOCUMENT", RelationshipType: "DESCRIBES", RelatedSPDXElement: distributionSPDXID04511(t.target)})
	}
	document["packages"] = packages
	document["relationships"] = relationships
	return nil
}

// Вызывается и прямым API подписания, и верификатором выпуска. Даже действительная подпись Ed25519
// не делает противоречивые BOM/SPDX/provenance пригодными к публикации.
func verifyDistributionSupplyChain04511(dir, ver string) error {
	if !distributionRequired04511(ver) {
		return nil
	}
	read := func(name string, dst any) error {
		p := filepath.Join(dir, name)
		st, e := os.Lstat(p)
		if e != nil {
			return e
		}
		if !st.Mode().IsRegular() || st.Size() == 0 || st.Size() > 64*1024*1024 {
			return fmt.Errorf("Небезопасный объект: %s", name)
		}
		raw, e := os.ReadFile(p)
		if e != nil {
			return e
		}
		return json.Unmarshal(raw, dst)
	}
	var sbom struct {
		SPDXVersion string `json:"spdxVersion"`
		SPDXID      string `json:"SPDXID"`
		Packages    []struct {
			SPDXID    string              `json:"SPDXID"`
			Name      string              `json:"name"`
			Version   string              `json:"versionInfo"`
			Checksums []sbomChecksum04511 `json:"checksums"`
		} `json:"packages"`
		Relationships []sbomRelationship `json:"relationships"`
	}
	if err := read("SBOM.spdx.json", &sbom); err != nil {
		return fmt.Errorf("SPDX: %w", err)
	}
	if sbom.SPDXVersion != "SPDX-2.3" || sbom.SPDXID != "SPDXRef-DOCUMENT" {
		return errors.New("Документ не соответствует формату SPDX 2.3")
	}
	ids := map[string]bool{}
	found := map[string]bool{}
	for _, p := range sbom.Packages {
		if p.SPDXID == "" || ids[p.SPDXID] {
			return fmt.Errorf("duplicate/empty SPDX package id: %s", p.SPDXID)
		}
		ids[p.SPDXID] = true
		if !strings.HasPrefix(p.SPDXID, "SPDXRef-Distribution-") {
			continue
		}
		target := strings.TrimPrefix(p.SPDXID, "SPDXRef-Distribution-")
		match := false
		for _, t := range distributionTargets04511(ver) {
			if target != t.target {
				continue
			}
			match = true
			hash, err := distributionHash04511(dir, t.packageFile)
			if err != nil {
				return err
			}
			if found[target] || p.Name != t.packageFile || p.Version != ver || len(p.Checksums) != 1 || p.Checksums[0].Algorithm != "SHA256" || p.Checksums[0].ChecksumValue != hash {
				return fmt.Errorf("SPDX shipped package checksum mismatch: %s", target)
			}
			found[target] = true
		}
		if !match {
			return fmt.Errorf("unexpected distribution SPDX target: %s", target)
		}
	}
	if len(found) != 6 {
		return errors.New("SPDX must describe exactly six final platform packages")
	}
	// Таблица из шести пакетов не является SBOM зависимостей. Сохраняйте исходные корни
	// приложений и граф зависимостей в подписанном документе.
	for _, root := range []string{"SPDXRef-Package-CLI", "SPDXRef-Package-BackendAPI", "SPDXRef-Package-Admin", "SPDXRef-Package-Desktop", "SPDXRef-Package-Runtime", "SPDXRef-Package-Bridges"} {
		if !ids[root] {
			return fmt.Errorf("dependency SBOM missing existing application root: %s", root)
		}
	}
	dependencyEdges := 0
	for _, r := range sbom.Relationships {
		if r.RelationshipType == "DEPENDS_ON" {
			dependencyEdges++
		}
	}
	if dependencyEdges == 0 {
		return errors.New("SPDX dependency graph is empty")
	}
	for _, t := range distributionTargets04511(ver) {
		linked := 0
		for _, r := range sbom.Relationships {
			if r.SPDXElementID == "SPDXRef-DOCUMENT" && r.RelationshipType == "DESCRIBES" && r.RelatedSPDXElement == distributionSPDXID04511(t.target) {
				linked++
			}
		}
		if linked != 1 {
			return fmt.Errorf("SPDX shipping relationship missing/duplicated: %s", t.target)
		}
	}
	var provenance struct {
		Type          string `json:"_type"`
		PredicateType string `json:"predicateType"`
		Subject       []struct {
			Name   string            `json:"name"`
			Digest map[string]string `json:"digest"`
		} `json:"subject"`
		Predicate struct {
			BuildDefinition struct {
				ExternalParameters struct {
					Version      string `json:"version"`
					SourceCommit string `json:"sourceCommit"`
				} `json:"externalParameters"`
				ResolvedDependencies []struct {
					URI    string            `json:"uri"`
					Digest map[string]string `json:"digest"`
				} `json:"resolvedDependencies"`
			} `json:"buildDefinition"`
		} `json:"predicate"`
	}
	if err := read("PROVENANCE.json", &provenance); err != nil {
		return fmt.Errorf("provenance: %w", err)
	}
	var manifest struct {
		Version      string `json:"version"`
		SourceCommit string `json:"sourceCommit"`
	}
	if err := read("RELEASE_MANIFEST.json", &manifest); err != nil {
		return err
	}
	if manifest.Version != ver || !(len(manifest.SourceCommit) == 40 || len(manifest.SourceCommit) == 64) || !regexp.MustCompile(`^[a-f0-9]+$`).MatchString(manifest.SourceCommit) || provenance.Type != "https://in-toto.io/Statement/v1" || provenance.PredicateType != "https://slsa.dev/provenance/v1" || provenance.Predicate.BuildDefinition.ExternalParameters.Version != ver || provenance.Predicate.BuildDefinition.ExternalParameters.SourceCommit != manifest.SourceCommit {
		return errors.New("SLSA source commit or release identity mismatch")
	}
	subjects := map[string]bool{}
	for _, s := range provenance.Subject {
		if s.Name == "" || subjects[s.Name] || filepath.Base(s.Name) != s.Name {
			return fmt.Errorf("unsafe or duplicate provenance subject %s", s.Name)
		}
		digest, err := distributionHash04511(dir, s.Name)
		if err != nil {
			return err
		}
		if len(s.Digest) != 1 || s.Digest["sha256"] != digest {
			return fmt.Errorf("provenance subject differs from actual file: %s", s.Name)
		}
		subjects[s.Name] = true
	}
	if !subjects["SBOM.spdx.json"] {
		return errors.New("provenance does not bind SPDX")
	}
	// Хеши исходных материалов должны совпадать с независимо закреплёнными
	// входами BOM; это реальные разрешённые зависимости SLSA, а не
	// утверждение, скопированное из поля версии.
	var bom struct {
		Components []struct {
			SourceFile   string `json:"sourceFile"`
			SourceSHA256 string `json:"sourceSha256"`
		} `json:"components"`
	}
	if err := read("RELEASE_BOM.json", &bom); err != nil {
		return fmt.Errorf("BOM: %w", err)
	}
	componentHashes := map[string]string{}
	for _, c := range bom.Components {
		componentHashes[c.SourceFile] = c.SourceSHA256
	}
	materials := map[string]string{}
	for _, m := range provenance.Predicate.BuildDefinition.ResolvedDependencies {
		if !strings.HasPrefix(m.URI, "file://") || len(m.Digest) != 1 || !bomSHA03214(m.Digest["sha256"]) || materials[m.URI] != "" {
			return errors.New("invalid/duplicate SLSA material")
		}
		materials[m.URI] = m.Digest["sha256"]
		if hash, ok := componentHashes[strings.TrimPrefix(m.URI, "file://")]; ok && hash != m.Digest["sha256"] {
			return fmt.Errorf("SLSA material differs from BOM: %s", m.URI)
		}
	}
	for _, source := range []string{"cli/go.mod", "services/api/go.mod", "apps/admin/package-lock.json", "apps/desktop/package-lock.json"} {
		uri := "file://" + source
		if componentHashes[source] == "" || materials[uri] != componentHashes[source] {
			return fmt.Errorf("SLSA mandatory material missing or changed: %s", source)
		}
	}
	for _, t := range distributionTargets04511(ver) {
		if !subjects[t.packageFile] {
			return fmt.Errorf("provenance missing signed package: %s", t.target)
		}
	}
	var receipt struct {
		Version string `json:"version"`
		Commit  string `json:"commit"`
		Status  string `json:"status"`
		Targets []struct {
			Target        string `json:"target"`
			Package       string `json:"package"`
			PackageSHA256 string `json:"packageSha256"`
		} `json:"targets"`
	}
	if err := read("GA_VERIFIED_TARGETS.json", &receipt); err != nil {
		return fmt.Errorf("independent GA: %w", err)
	}
	if receipt.Version != ver || receipt.Commit != manifest.SourceCommit || receipt.Status != "approved-for-release-signing" || len(receipt.Targets) != 6 {
		return errors.New("independent GA identity or number of targets mismatch")
	}
	seen := map[string]bool{}
	for _, r := range receipt.Targets {
		match := false
		for _, t := range distributionTargets04511(ver) {
			if r.Target == t.target {
				match = true
				digest, err := distributionHash04511(dir, t.packageFile)
				if err != nil {
					return err
				}
				if seen[t.target] || r.Package != t.packageFile || r.PackageSHA256 != digest {
					return fmt.Errorf("GA approval package differs from final signed package: %s", t.target)
				}
				seen[t.target] = true
			}
		}
		if !match {
			return errors.New("independent GA contains unexpected target")
		}
	}
	return nil
}
