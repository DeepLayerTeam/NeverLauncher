package main

import "testing"

func TestBackupCLIRequiresInputsAndExplicitReplace(t *testing.T) {
	for _, tc := range [][]string{
		{"backup"}, {"backup", "--db", "/a"}, {"pre-upgrade", "--backup", "/b"},
		{"restore", "--backup", "/b"}, {"backup-verify", "--replace", "--backup", "/x"},
	} {
		if code := runBackupAction(tc); code != 2 {
			t.Fatalf("%v вернул код %d; ожидался код неверного использования 2", tc, code)
		}
	}
}
