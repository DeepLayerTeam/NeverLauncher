package repository

import (
	"context"
	"errors"
	"sync"
	"testing"
)

const testClientID02611 = "11223344-5566-7788-99aa-bbccddeeff00"

func TestOfficialProviderPolicyValidation02611(t *testing.T) {
	p := DefaultOfficialProvider02611(testClientID02611)
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []OfficialProviderSettings02611{
		{ClientID: "not-a-uuid", Enabled: true, BrowserEnabled: true, Issuer: "consumers"},
		{ClientID: testClientID02611, Enabled: true, Issuer: "consumers"},
		{ClientID: testClientID02611, Enabled: true, BrowserEnabled: true, Issuer: "common"},
		{ClientID: "", Enabled: true, BrowserEnabled: true, Issuer: "consumers"},
	} {
		if err := bad.Validate(); err == nil {
			t.Fatalf("accepted invalid configuration: %+v", bad)
		}
	}
}
func TestOfficialProviderConcurrentCASAndHistory02611(t *testing.T) {
	r := &MemoryRepository{}
	p := DefaultOfficialProvider02611(testClientID02611)
	const contenders = 8
	successes := make(chan OfficialProviderRevision02611, contenders)
	var wg sync.WaitGroup
	for i := 0; i < contenders; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rev, err := r.SaveOfficialProvider02611(context.Background(), 0, p, "admin", "configure original provider")
			if err == nil {
				successes <- rev
			} else if !errors.Is(err, ErrOfficialProviderConflict02611) {
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()
	close(successes)
	count := 0
	for range successes {
		count++
	}
	if count != 1 {
		t.Fatalf("expected one winner, got %d", count)
	}
	p.DeviceEnabled = false
	second, err := r.SaveOfficialProvider02611(context.Background(), 1, p, "admin", "disable device code")
	if err != nil || second.Revision != 2 {
		t.Fatalf("expected revision 2: %v %+v", err, second)
	}
	history, err := r.ListOfficialProviderHistory02611(context.Background(), 10)
	if err != nil || len(history) != 2 || history[0].Revision != 2 || history[1].Revision != 1 {
		t.Fatalf("broken history: %v %+v", err, history)
	}
}
