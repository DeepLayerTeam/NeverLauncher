package httpapi

import (
	"strings"
	"testing"
)

func TestExtensionHTMLCSPPrecedesUntrustedMarkup0356(t *testing.T) {
	for _, dangerous := range []string{
		`<script>window.evil=true</script><head><title>x</title></head>`,
		`<html><HEAD onload="evil()"><script>evil()</script></HEAD></html>`,
		`<svg onload="evil()"></svg>`,
	} {
		got := hardenAdminHTML0208(dangerous)
		pos := strings.Index(got, dangerous)
		csp := strings.Index(got, `http-equiv="Content-Security-Policy"`)
		if csp < 0 || pos < 0 || csp > pos || !strings.Contains(got, "connect-src 'none'") || !strings.Contains(got, "form-action 'none'") || !strings.Contains(got, "worker-src 'none'") {
			t.Fatalf("CSP was not installed before untrusted input: %q", got)
		}
	}
}
