package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const forgeProcessorJournalSchema = "1.0"

type forgeProcessorJournalEntry struct {
	IdentitySHA256 string `json:"identitySha256"`
	State          string `json:"state"`
	Attempts       int    `json:"attempts"`
	Recovered      bool   `json:"recovered,omitempty"`
	LastError      string `json:"lastError,omitempty"`
	UpdatedAt      string `json:"updatedAt"`
}

type forgeProcessorJournal struct {
	SchemaVersion    string                                `json:"schemaVersion"`
	Loader           string                                `json:"loader"`
	MinecraftVersion string                                `json:"minecraftVersion"`
	InstallerSHA256  string                                `json:"installerSha256"`
	Entries          map[string]forgeProcessorJournalEntry `json:"entries"`
}

func forgeProcessorJournalPath(pc forgeProcessorContext) string {
	return filepath.Join(filepath.Dir(pc.InstallerPath), "processor-journal.json")
}

func loadForgeProcessorJournal(pc forgeProcessorContext) (forgeProcessorJournal, bool, error) {
	_, installerSHA, _, err := hashFileSHA1SHA256(pc.InstallerPath)
	if err != nil {
		return forgeProcessorJournal{}, false, fmt.Errorf("processor journal installer hash: %w", err)
	}
	fresh := forgeProcessorJournal{
		SchemaVersion:    forgeProcessorJournalSchema,
		Loader:           strings.ToLower(strings.TrimSpace(pc.Loader)),
		MinecraftVersion: strings.TrimSpace(pc.MinecraftVersion),
		InstallerSHA256:  strings.ToLower(installerSHA),
		Entries:          map[string]forgeProcessorJournalEntry{},
	}
	path := forgeProcessorJournalPath(pc)
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return fresh, false, nil
	}
	if err != nil {
		return forgeProcessorJournal{}, false, err
	}
	var journal forgeProcessorJournal
	if err := json.Unmarshal(raw, &journal); err != nil {
		_ = quarantineProcessorJournal(pc, "processor journal JSON is corrupt")
		return fresh, true, nil
	}
	if journal.SchemaVersion != forgeProcessorJournalSchema || journal.Loader != fresh.Loader || journal.MinecraftVersion != fresh.MinecraftVersion || !strings.EqualFold(journal.InstallerSHA256, fresh.InstallerSHA256) || journal.Entries == nil {
		_ = quarantineProcessorJournal(pc, "processor journal identity mismatch")
		return fresh, true, nil
	}
	return journal, false, nil
}

func persistForgeProcessorJournal(pc forgeProcessorContext, journal forgeProcessorJournal) (string, error) {
	journal.SchemaVersion = forgeProcessorJournalSchema
	if journal.Entries == nil {
		journal.Entries = map[string]forgeProcessorJournalEntry{}
	}
	raw, err := json.MarshalIndent(journal, "", "  ")
	if err != nil {
		return "", err
	}
	raw = append(raw, '\n')
	path := forgeProcessorJournalPath(pc)
	if err := writeAtomicBytes(path, raw, 0o600); err != nil {
		return "", err
	}
	return sha256HexBytes(raw), nil
}

func quarantineProcessorJournal(pc forgeProcessorContext, reason string) error {
	path := forgeProcessorJournalPath(pc)
	rel, err := filepath.Rel(pc.ClientDir, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return fmt.Errorf("processor journal is outside client root: %s", path)
	}
	_, err = quarantineCompatibilityArtifact(pc.ClientDir, filepath.ToSlash(rel), reason)
	return err
}

func forgeProcessorIdentity(pc forgeProcessorContext, index int, processor forgeProcessor) string {
	identity := struct {
		Index     int               `json:"index"`
		Loader    string            `json:"loader"`
		Minecraft string            `json:"minecraft"`
		Jar       string            `json:"jar"`
		Classpath []string          `json:"classpath"`
		Args      []string          `json:"args"`
		Outputs   map[string]string `json:"outputs"`
	}{
		Index:     index,
		Loader:    strings.ToLower(strings.TrimSpace(pc.Loader)),
		Minecraft: strings.TrimSpace(pc.MinecraftVersion),
		Jar:       processor.Jar,
		Classpath: append([]string(nil), processor.Classpath...),
		Args:      append([]string(nil), processor.Args...),
		Outputs:   processor.Outputs,
	}
	raw, _ := json.Marshal(identity)
	return sha256HexBytes(raw)
}

func processorJournalKey(index int) string {
	return strconv.Itoa(index)
}

func markProcessorJournal(pc forgeProcessorContext, journal *forgeProcessorJournal, index int, identity, state string, recovered bool, lastErr string) (string, error) {
	key := processorJournalKey(index)
	entry := journal.Entries[key]
	if entry.IdentitySHA256 != identity {
		entry = forgeProcessorJournalEntry{IdentitySHA256: identity}
	}
	if state == "running" {
		entry.Attempts++
	}
	entry.State = state
	entry.Recovered = recovered
	entry.LastError = strings.TrimSpace(lastErr)
	if len(entry.LastError) > 2048 {
		entry.LastError = entry.LastError[:2048]
	}
	entry.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	journal.Entries[key] = entry
	return persistForgeProcessorJournal(pc, *journal)
}

func quarantineProcessorOutputs(pc forgeProcessorContext, processor forgeProcessor, reason string) error {
	for outputToken := range processor.Outputs {
		outputPath, err := resolveProcessorToken(pc, outputToken)
		if err != nil {
			return err
		}
		root, err := filepath.Abs(pc.ClientDir)
		if err != nil {
			return err
		}
		abs, err := filepath.Abs(outputPath)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, abs)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			return fmt.Errorf("processor output вышел за client root: %s", outputPath)
		}
		if _, err := os.Lstat(abs); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return err
		}
		if _, err := quarantineCompatibilityArtifact(pc.ClientDir, filepath.ToSlash(rel), reason); err != nil {
			return err
		}
	}
	return nil
}
