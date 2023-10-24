// Package metadatatestutils contains utilities for testing binary metadata.
package metadatatestutils

import (
	"fmt"
	"testing"

	"google3/privacy/net/common/cpp/public_metadata/go/binarymetadata"
	"google3/third_party/golang/cmp/cmp"
)

// Equal checks if a and b are equal under testing requirements.
func Equal(t *testing.T, a, b []byte) {
	t.Helper()
	bmA, err := binarymetadata.Deserialize(a)
	if err != nil {
		t.Fatalf("Deserialize(%v): %v", a, err)
	}
	bmB, err := binarymetadata.Deserialize(b)
	if err != nil {
		t.Fatalf("Deserialize(%v): %v", b, err)
	}
	if bmA.GetDebugMode() != bmB.GetDebugMode() {
		diff, err := fmt.Printf("-want %v, go %v", bmA.GetDebugMode(), bmB.GetDebugMode())
		if err != nil {
			t.Error(diff)
		}
		t.Error(err)
	}
	if diff := cmp.Diff(bmA.GetGeoHint(), bmB.GetGeoHint()); diff != "" {
		t.Errorf("unexpected diff: %v", diff)
	}
	if bmA.GetServiceType() != bmB.GetServiceType() {
		t.Errorf("-want %v, got %v", bmA.GetServiceType(), bmB.GetServiceType())
	}
}

// Serialize is a test only way to serialize binary metadata.
func Serialize(t *testing.T, fields *binarymetadata.NewBinaryFields) []byte {
	t.Helper()
	binmd := binarymetadata.New(fields)
	defer binmd.Free()
	exts, err := binarymetadata.Serialize(binmd)
	if err != nil {
		t.Fatalf("Serialize(): %v", err)
	}
	return exts
}
