package extensionjava

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const HostMain = "ru.launcher.sdk.host.JavaExtensionHost"

var className = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$.]{1,200}$`)
var javaVersionPattern = regexp.MustCompile(`(?:java|openjdk) version "(?:1\.)?(\d+)(?:[.\-+"_]|$)`)

type JarInfo struct {
	EntrypointClass   string `json:"entrypointClass"`
	GravitModuleClass string `json:"gravitModuleClass,omitempty"`
	ClassFiles        int    `json:"classFiles"`
	MaxClassMajor     int    `json:"maxClassMajor"`
	MinimumJava       int    `json:"minimumJava"`
}

type RuntimeInfo struct {
	Executable string `json:"executable"`
	Feature    int    `json:"feature"`
}

// Inspect verifies an extracted Java host JAR without executing its code.
// It is not a signature verifier or a malware scanner.
func Inspect(file string) (JarInfo, error) {
	st, err := os.Lstat(file)
	if err != nil {
		return JarInfo{}, err
	}
	if !st.Mode().IsRegular() || st.Mode()&os.ModeSymlink != 0 || st.Size() < 64 || st.Size() > 128<<20 {
		return JarInfo{}, errors.New("JAR must be regular non-symlink file of at most 128 MiB")
	}
	zr, err := zip.OpenReader(file)
	if err != nil {
		return JarInfo{}, fmt.Errorf("open JAR: %w", err)
	}
	defer zr.Close()
	if len(zr.File) > 4096 {
		return JarInfo{}, errors.New("too many JAR entries")
	}
	seen := map[string]bool{}
	classes := map[string]bool{}
	var descriptor *zip.File
	var total uint64
	result := JarInfo{MinimumJava: 17}
	for _, f := range zr.File {
		name := f.Name
		if name == "" || name == "." || strings.HasPrefix(name, "./") || strings.ContainsAny(name, "\\\x00") || strings.HasPrefix(name, "/") || path.Clean(name) != strings.TrimSuffix(name, "/") || strings.HasPrefix(name, "../") || name == ".." || strings.Contains(name, "//") {
			return JarInfo{}, fmt.Errorf("unsafe JAR entry %q", name)
		}
		if seen[name] {
			return JarInfo{}, fmt.Errorf("duplicate JAR entry %q", name)
		}
		seen[name] = true
		if f.Mode()&os.ModeSymlink != 0 {
			return JarInfo{}, errors.New("JAR contains symlink")
		}
		if f.UncompressedSize64 > 32<<20 {
			return JarInfo{}, fmt.Errorf("oversized JAR entry %q", name)
		}
		total += f.UncompressedSize64
		if total > 384<<20 {
			return JarInfo{}, errors.New("JAR expanded size exceeds limit")
		}
		if name == "META-INF/MANIFEST.MF" {
			descriptor = f
		}
		if !strings.HasSuffix(name, ".class") {
			continue
		}
		classes[name] = true
		result.ClassFiles++
		if f.UncompressedSize64 < 8 {
			return JarInfo{}, fmt.Errorf("truncated class %q", name)
		}
		r, e := f.Open()
		if e != nil {
			return JarInfo{}, e
		}
		header := make([]byte, 8)
		_, e = io.ReadFull(r, header)
		if e == nil {
			// Finish the stream so the ZIP CRC is actually checked, not merely the header.
			_, e = io.Copy(io.Discard, r)
		}
		closeErr := r.Close()
		if e != nil {
			return JarInfo{}, fmt.Errorf("read class %s: %w", name, e)
		}
		if closeErr != nil {
			return JarInfo{}, closeErr
		}
		if binary.BigEndian.Uint16(header[4:6]) == 65535 {
			return JarInfo{}, fmt.Errorf("preview bytecode %s is not supported without --enable-preview", name)
		}
		if binary.BigEndian.Uint32(header[:4]) != 0xCAFEBABE {
			return JarInfo{}, fmt.Errorf("invalid class magic %q", name)
		}
		major := int(binary.BigEndian.Uint16(header[6:8]))
		if major < 45 || major > 100 {
			return JarInfo{}, fmt.Errorf("unsupported class version %d in %q", major, name)
		}
		if major > result.MaxClassMajor {
			result.MaxClassMajor = major
		}
	}
	if descriptor == nil || descriptor.UncompressedSize64 > 65536 {
		return JarInfo{}, errors.New("JAR manifest missing or oversized")
	}
	r, err := descriptor.Open()
	if err != nil {
		return JarInfo{}, err
	}
	data, err := io.ReadAll(io.LimitReader(r, 65537))
	_ = r.Close()
	if err != nil {
		return JarInfo{}, err
	}
	if len(data) > 65536 {
		return JarInfo{}, errors.New("JAR manifest exceeds limit")
	}
	attrs := map[string]string{}
	current := ""
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	for _, line := range lines {
		if line == "" {
			break
		}
		if strings.HasPrefix(line, " ") {
			if current == "" {
				return JarInfo{}, errors.New("orphan JAR manifest continuation")
			}
			attrs[current] += line[1:]
			continue
		}
		parts := strings.SplitN(line, ": ", 2)
		if len(parts) != 2 {
			return JarInfo{}, errors.New("malformed JAR manifest")
		}
		current = strings.ToLower(parts[0])
		if _, exists := attrs[current]; exists {
			return JarInfo{}, errors.New("duplicate JAR manifest attribute")
		}
		attrs[current] = parts[1]
	}
	if attrs["main-class"] != HostMain {
		return JarInfo{}, fmt.Errorf("JAR Main-Class must be %s", HostMain)
	}
	class := attrs["launcher-extension-class"]
	if !className.MatchString(class) || strings.Contains(class, "..") || strings.HasPrefix(class, ".") || strings.HasSuffix(class, ".") {
		return JarInfo{}, errors.New("invalid Launcher-Extension-Class")
	}
	if _, ok := attrs["class-path"]; ok {
		return JarInfo{}, errors.New("external JAR Class-Path is forbidden")
	}
	if !classes[strings.ReplaceAll(class, ".", "/")+".class"] {
		return JarInfo{}, errors.New("declared extension class absent from JAR")
	}
	// The Gravit adapter is opt-in, with a fixed entrypoint and an explicit
	// ported module. Never treat arbitrary Gravit JARs as compatible.
	const gravitAdapter = "ru.launcher.sdk.gravit.GravitCompatExtension"
	portedModule := attrs["launcher-gravit-module-class"]
	if class == gravitAdapter {
		if !className.MatchString(portedModule) || strings.Contains(portedModule, "..") || strings.HasPrefix(portedModule, ".") || strings.HasSuffix(portedModule, ".") || strings.HasPrefix(portedModule, "pro.gravit.launcher.") || strings.HasPrefix(portedModule, "ru.launcher.sdk.") {
			return JarInfo{}, errors.New("Gravit compatibility package requires valid Launcher-Gravit-Module-Class")
		}
		if !classes[strings.ReplaceAll(portedModule, ".", "/")+".class"] {
			return JarInfo{}, errors.New("ported Gravit module class absent from JAR")
		}
		if !classes["ru/launcher/sdk/gravit/GravitCompatExtension.class"] {
			return JarInfo{}, errors.New("Gravit compatibility runtime class absent from JAR")
		}
		result.GravitModuleClass = portedModule
	} else if portedModule != "" {
		return JarInfo{}, errors.New("Gravit module class requires the explicit compatibility adapter entrypoint")
	}
	if !classes["ru/launcher/sdk/host/JavaExtensionHost.class"] {
		return JarInfo{}, errors.New("Java Extension Host class absent from JAR")
	}
	result.EntrypointClass = class
	if result.MaxClassMajor > 61 {
		result.MinimumJava = result.MaxClassMajor - 44
	}
	return result, nil
}

// ProbeRuntime checks the actual JVM executable with an enforced deadline.
func ProbeRuntime(ctx context.Context, javaBinary string, requiredFeature int) (RuntimeInfo, error) {
	javaBinary = strings.TrimSpace(javaBinary)
	if javaBinary == "" {
		var err error
		javaBinary, err = exec.LookPath("java")
		if err != nil {
			return RuntimeInfo{}, fmt.Errorf("Java runtime not found: %w", err)
		}
	} else {
		if !filepath.IsAbs(javaBinary) {
			return RuntimeInfo{}, errors.New("configured Java executable must be absolute")
		}
		st, err := os.Lstat(javaBinary)
		if err != nil {
			return RuntimeInfo{}, err
		}
		if !st.Mode().IsRegular() || st.Mode()&os.ModeSymlink != 0 {
			return RuntimeInfo{}, errors.New("configured Java executable must be regular, not symlink")
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, javaBinary, "-version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return RuntimeInfo{}, fmt.Errorf("Java runtime probe failed: %w", err)
	}
	output = bytes.TrimSpace(output)
	if len(output) > 4096 {
		return RuntimeInfo{}, errors.New("Java runtime output too long")
	}
	match := javaVersionPattern.FindSubmatch(output)
	if len(match) != 2 {
		return RuntimeInfo{}, errors.New("unrecognised Java runtime version")
	}
	feature, err := strconv.Atoi(string(match[1]))
	if err != nil {
		return RuntimeInfo{}, err
	}
	if feature < 17 || feature < requiredFeature {
		return RuntimeInfo{}, fmt.Errorf("Java %d cannot load required Java %d bytecode", feature, requiredFeature)
	}
	return RuntimeInfo{Executable: javaBinary, Feature: feature}, nil
}
