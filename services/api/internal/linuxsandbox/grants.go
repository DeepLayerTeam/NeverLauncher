package linuxsandbox

import (
	"net"
	"regexp"
	"strconv"
	"strings"
)

var grantName03110 = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)

func validResourceName03110(v string) bool { return grantName03110.MatchString(v) }
func validSharedGrant03110(v string) bool {
	return strings.HasPrefix(v, "shared:") && validResourceName03110(strings.TrimPrefix(v, "shared:"))
}
func validDestination03110(v string) bool {
	host, port, err := net.SplitHostPort(v)
	if err != nil || len(host) == 0 || host != strings.ToLower(host) || strings.HasSuffix(host, ".") || strings.ContainsAny(host, "/%*\\ ") || net.ParseIP(host) != nil {
		return false
	}
	for _, r := range host {
		if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '-') {
			return false
		}
	}
	n, err := strconv.Atoi(port)
	return err == nil && n > 0 && n <= 65535 && strconv.Itoa(n) == port
}
