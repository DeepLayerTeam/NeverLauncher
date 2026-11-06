package httpapi

import (
	"mime/multipart"
	"net/http/httptest"
	"testing"
)

func TestReleaseFileMetadataNormalizesTargetOS(t *testing.T) {
	req := httptest.NewRequest("POST", "/upload", nil)
	req.MultipartForm = &multipart.Form{Value: map[string][]string{
		"executable": {"true"},
		"targetOs":   {"win, linux", "darwin"},
	}}
	executable, targets, err := releaseFileMetadata(req)
	if err != nil {
		t.Fatal(err)
	}
	if !executable {
		t.Fatal("Значение executable=true должно сохраняться")
	}
	want := []string{"linux", "osx", "windows"}
	if len(targets) != len(want) {
		t.Fatalf("unexpected targets: %#v", targets)
	}
	for i := range want {
		if targets[i] != want[i] {
			t.Fatalf("unexpected targets: %#v", targets)
		}
	}
}

func TestReleaseFileMetadataRejectsUnknownTargetOS(t *testing.T) {
	req := httptest.NewRequest("POST", "/upload", nil)
	req.MultipartForm = &multipart.Form{Value: map[string][]string{"targetOs": {"plan9"}}}
	if _, _, err := releaseFileMetadata(req); err == nil {
		t.Fatal("Неизвестная целевая ОС должна быть отклонена")
	}
}
