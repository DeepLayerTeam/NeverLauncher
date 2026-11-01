package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLiveVerificationRejectsRevokedCutoverAndChangedReview0450(t *testing.T) {
	root := t.TempDir()
	archive := filepath.Join(root, "gravit.zip")
	if err := os.WriteFile(archive, createSourceZIP(t), 0600); err != nil {
		t.Fatal(err)
	}
	sourceSHA, err := shaFile(archive, 512<<20)
	if err != nil {
		t.Fatal(err)
	}
	report := sampleReport(t, sourceSHA)
	review := Review{Report: report, ReviewedBy: "operator", EvidenceSHA256: testHash, ReviewedAt: "2026-01-01T00:00:00Z", Status: "rc_reviewed_not_ga_certified"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(w, "forbidden", 403)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/review") {
			json.NewEncoder(w).Encode(map[string]any{"data": review})
		} else {
			json.NewEncoder(w).Encode(map[string]any{"data": report})
		}
	}))
	defer server.Close()
	p := Plan{ReferenceClass: "fileauth-single", Backend: server.URL, RunID: report.RunID, ProjectID: report.ProjectID, SourceArchive: archive, CommitSHA: testHash, SourceVersion: "5.7.4", TrustedGravitJarSHA256: trustedJarHash(t), TargetReleaseSHA256: testHash}
	b := Bundle{ReferenceClass: p.ReferenceClass, RunID: p.RunID, ProjectID: p.ProjectID, CommitSHA: p.CommitSHA, SourceVersion: p.SourceVersion, TrustedGravitJarSHA256: p.TrustedGravitJarSHA256, TargetReleaseSHA256: p.TargetReleaseSHA256, SourceSHA256: sourceSHA, ReportSHA256: report.ReportSHA256, ReviewedBy: review.ReviewedBy, ReviewEvidenceSHA256: review.EvidenceSHA256}
	if err := verifyLiveReference(context.Background(), b, p, "test-token"); err != nil {
		t.Fatal(err)
	}
	if err := verifyLiveReference(context.Background(), b, p, ""); err == nil {
		t.Fatal("missing token accepted")
	}
	report.Evidence[len(report.Evidence)-1].Details = "cancelled"
	report.ReportSHA256 = ""
	raw, _ := json.Marshal(report)
	report.ReportSHA256 = hash(raw)
	if err := verifyLiveReference(context.Background(), b, p, "test-token"); err == nil {
		t.Fatal("revoked cutover accepted")
	}
	report = sampleReport(t, sourceSHA)
	review.ReviewedBy = "different"
	if err := verifyLiveReference(context.Background(), b, p, "test-token"); err == nil {
		t.Fatal("changed operator review accepted")
	}
}
