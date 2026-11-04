package extensionhost

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// prepareJavaScratch04811 creates private writable Java user state and appends
// VM properties before -jar. The caller must remove this directory after the
// child has been reaped. It does not claim kernel filesystem isolation.
func prepareJavaScratch04811(cmd *exec.Cmd) (string, error) {
	if cmd == nil || len(cmd.Args) < 3 {
		return "", errors.New("missing Java command")
	}
	jarAt := -1
	for i, arg := range cmd.Args {
		if arg == "-jar" {
			jarAt = i
			break
		}
	}
	if jarAt < 1 || jarAt+1 >= len(cmd.Args) {
		return "", errors.New("Java command missing -jar")
	}
	scratch, err := os.MkdirTemp("", "neverlauncher-java-04811-")
	if err != nil {
		return "", err
	}
	fail := func(e error) (string, error) { _ = os.RemoveAll(scratch); return "", e }
	if err := os.Chmod(scratch, 0700); err != nil {
		return fail(err)
	}
	for _, name := range []string{"tmp", "home"} {
		if err := os.Mkdir(filepath.Join(scratch, name), 0700); err != nil {
			return fail(err)
		}
	}
	home := filepath.Join(scratch, "home")
	tmp := filepath.Join(scratch, "tmp")
	flags := []string{"-Djava.io.tmpdir=" + tmp, "-Duser.home=" + home}
	cmd.Args = append(append(append([]string{}, cmd.Args[:jarAt]...), flags...), cmd.Args[jarAt:]...)
	env := make([]string, 0, len(cmd.Env)+5)
	for _, entry := range cmd.Env {
		upper := strings.ToUpper(strings.SplitN(entry, "=", 2)[0])
		switch upper {
		case "HOME", "TMP", "TEMP", "TMPDIR", "USERPROFILE", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME":
			continue
		}
		env = append(env, entry)
	}
	cmd.Env = append(env, "HOME="+home, "TMP="+tmp, "TEMP="+tmp,
		"TMPDIR="+tmp, "XDG_CONFIG_HOME="+home, "XDG_CACHE_HOME="+home)
	return scratch, nil
}

func redactHostCredentials04811(input string, tokens ...string) string {
	for _, token := range tokens {
		// Empty credentials cannot be replaced (strings.ReplaceAll would
		// interpolate a replacement at every byte).
		if len(token) >= 16 {
			input = strings.ReplaceAll(input, token, "[REDACTED]")
		}
	}
	return input
}

func redactHostLogFields04811(fields map[string]any, tokens ...string) map[string]any {
	if len(fields) == 0 {
		return fields
	}
	out := make(map[string]any, len(fields))
	for k, v := range fields {
		lower := strings.ToLower(k)
		if strings.Contains(lower, "token") || strings.Contains(lower, "secret") || strings.Contains(lower, "password") || strings.Contains(lower, "authorization") || strings.Contains(lower, "credential") {
			out[k] = "[REDACTED]"
			continue
		}
		switch typed := v.(type) {
		case string:
			out[k] = redactHostCredentials04811(typed, tokens...)
		case map[string]any:
			out[k] = redactHostLogFields04811(typed, tokens...)
		case []any:
			values := make([]any, len(typed))
			for i, item := range typed {
				switch nested := item.(type) {
				case string:
					values[i] = redactHostCredentials04811(nested, tokens...)
				case map[string]any:
					values[i] = redactHostLogFields04811(nested, tokens...)
				default:
					values[i] = item
				}
			}
			out[k] = values
		default:
			out[k] = v
		}
	}
	return out
}
