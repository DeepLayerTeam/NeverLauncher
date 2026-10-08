package httpapi

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

func releaseFileMetadata(r *http.Request) (bool, []string, error) {
	executable := false
	rawExecutable := ""
	if r.MultipartForm != nil && len(r.MultipartForm.Value["executable"]) > 0 {
		rawExecutable = r.MultipartForm.Value["executable"][0]
	}
	if strings.TrimSpace(rawExecutable) == "" {
		rawExecutable = r.FormValue("executable")
	}
	if raw := strings.TrimSpace(rawExecutable); raw != "" {
		value, err := strconv.ParseBool(raw)
		if err != nil {
			return false, nil, fmt.Errorf("executable должен быть true или false")
		}
		executable = value
	}

	values := make([]string, 0)
	if r.MultipartForm != nil {
		values = append(values, r.MultipartForm.Value["targetOs"]...)
	}
	if len(values) == 0 {
		if raw := strings.TrimSpace(r.FormValue("targetOs")); raw != "" {
			values = append(values, raw)
		}
	}
	seen := map[string]struct{}{}
	for _, raw := range values {
		for _, item := range strings.Split(raw, ",") {
			item = strings.ToLower(strings.TrimSpace(item))
			if item == "" || item == "all" || item == "any" {
				continue
			}
			switch item {
			case "windows", "win":
				item = "windows"
			case "linux":
				item = "linux"
			case "osx", "macos", "darwin":
				item = "osx"
			default:
				return false, nil, fmt.Errorf("неподдерживаемый targetOs %q", item)
			}
			seen[item] = struct{}{}
		}
	}
	targetOS := make([]string, 0, len(seen))
	for item := range seen {
		targetOS = append(targetOS, item)
	}
	sort.Strings(targetOS)
	return executable, targetOS, nil
}
