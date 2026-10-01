package main

import "testing"

func TestManagedJavaIIRequired0165(t *testing.T) {
	for _, ver := range []string{"0.16.5", "0.17.0", "1.0.0"} {
		if !managedJavaIIRequired0165(ver) {
			t.Fatalf("%s must require Managed Java II", ver)
		}
	}
	for _, ver := range []string{"0.16.4", "0.15.11"} {
		if managedJavaIIRequired0165(ver) {
			t.Fatalf("%s must not require Managed Java II", ver)
		}
	}
}

func TestManagedJavaIIMajors0165(t *testing.T) {
	got := managedJavaIIMajors0165()
	want := []int{8, 16, 17, 21, 25}
	if len(got) != len(want) {
		t.Fatalf("Managed Java II major count=%d want=%d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Managed Java II major[%d]=%d want=%d", i, got[i], want[i])
		}
	}
}
