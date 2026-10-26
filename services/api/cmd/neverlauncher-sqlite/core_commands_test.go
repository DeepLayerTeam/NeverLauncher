package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateJSONRejectsUnsafeFiles(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "input.json")
	if e := os.WriteFile(p, []byte(`{"id":"p"}`), 0644); e != nil {
		t.Fatal(e)
	}
	var v struct {
		ID string `json:"id"`
	}
	if e := readPrivateJSON(p, &v); e == nil {
		t.Fatal("public JSON input accepted")
	}
	if e := os.Chmod(p, 0600); e != nil {
		t.Fatal(e)
	}
	if e := readPrivateJSON(p, &v); e != nil || v.ID != "p" {
		t.Fatalf("private JSON should be accepted: %v %+v", e, v)
	}
	if e := os.WriteFile(p, []byte(`{"id":"p","privileged":true}`), 0600); e != nil {
		t.Fatal(e)
	}
	if e := readPrivateJSON(p, &v); e == nil {
		t.Fatal("unknown JSON fields accepted")
	}
	link := filepath.Join(dir, "link.json")
	if e := os.Symlink(p, link); e != nil {
		t.Fatal(e)
	}
	if e := readPrivateJSON(link, &v); e == nil {
		t.Fatal("symlink JSON input accepted")
	}
}
