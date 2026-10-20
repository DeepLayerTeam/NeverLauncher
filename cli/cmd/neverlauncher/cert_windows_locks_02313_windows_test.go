package main

import (
    "os"
    "path/filepath"
    "syscall"
    "testing"
    "unsafe"
)

// Test a real Windows sharing violation rather than a mocked permission error.
// The updater must fail safely without modifying a locked live binary.
func TestLockedWindowsExecutablePreservesOldRelease02313(t *testing.T) {
    dir := t.TempDir()
    dst := filepath.Join(dir, "neverguard.exe")
    src := filepath.Join(dir, "newguard.exe")
    userFile := filepath.Join(dir, "profiles", "world", "level.dat")
    if err := os.MkdirAll(filepath.Dir(userFile), 0755); err != nil { t.Fatal(err) }
    for p, v := range map[string]string{dst:"old-guard",src:"new-guard",userFile:"player-save"} {
        if err := os.WriteFile(p, []byte(v), 0644); err != nil { t.Fatal(err) }
    }
    kernel := syscall.NewLazyDLL("kernel32.dll")
    create := kernel.NewProc("CreateFileW")
    name, err := syscall.UTF16PtrFromString(dst)
    if err != nil { t.Fatal(err) }
    // GENERIC_READ | GENERIC_WRITE, dwShareMode = 0: no delete/rename access.
    h, _, callErr := create.Call(uintptr(unsafe.Pointer(name)), 0xC0000000, 0, 0, 3, 0x80, 0)
    if h == ^uintptr(0) {
        t.Fatalf("CreateFileW exclusive handle failed: %v", callErr)
    }
    closer := kernel.NewProc("CloseHandle")
    updater, err := newTransactionalUpdater0156(dir)
    if err != nil { t.Fatal(err) }
    _, err = updater.apply(updaterRequest0156{Root:dir, Namespace:"cert-win-lock",
        Files: []updaterFileSpec0156{updaterTestSpec0156(t, "neverguard.exe", src, true)}})
    closer.Call(h)
    if err == nil { t.Fatal("updater committed despite exclusive lock on live executable") }
    raw, err := os.ReadFile(dst)
    if err != nil || string(raw) != "old-guard" { t.Fatalf("locked original must remain: %q %v", raw, err) }
    save, err := os.ReadFile(userFile)
    if err != nil || string(save) != "player-save" { t.Fatalf("player data modified: %q %v", save, err) }
}
