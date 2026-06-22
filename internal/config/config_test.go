package config

import (
	"testing"
)

func TestAPIKeyRoundTrip(t *testing.T) {
	original, _ := GetAPIKey()
	defer SetAPIKey(original)

	if err := SetAPIKey("my-test-key"); err != nil {
		t.Fatalf("SetAPIKey failed: %v", err)
	}

	got, err := GetAPIKey()
	if err != nil {
		t.Fatalf("GetAPIKey failed: %v", err)
	}
	if got != "my-test-key" {
		t.Fatalf("expected my-test-key, got %q", got)
	}
}
