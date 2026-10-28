package main

import "testing"

func TestRollbackCLIRequiresWriterFences03312(t *testing.T) {
	cases := [][]string{
		{"rollback-plan", "--backend", "http://example.com", "--run", "test", "--token", "abc"},
		{"rollback-plan", "--backend", "https://server.test", "--run", "run-id", "--token", "abc", "--confirm", "wrong"},
		{"rollback-commit", "--backend", "https://server.test", "--run", "run-id", "--token", "abc", "--confirm", "run-id", "--never-writer-fenced", "true", "--expected-revision", "2", "--snapshot", "not-here"},
	}
	for _, args := range cases {
		if e := handleMigrationRollback03312(args); e == nil {
			t.Fatalf("unsafe command accepted: %v", args)
		}
	}
}
