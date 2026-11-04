package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

func rollbackSend03312(req *http.Request, out string) error {
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, e := client.Do(req)
	if e != nil {
		return e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("rollback HTTP %d; check durable state before retry", resp.StatusCode)
	}
	raw, e := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if e != nil {
		return e
	}
	var decoded map[string]any
	if e = json.Unmarshal(raw, &decoded); e != nil {
		return e
	}
	return writePrivateIdentityReport0334(out, decoded)
}
