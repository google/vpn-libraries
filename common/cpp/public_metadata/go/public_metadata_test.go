package binarymetadata

import (
	"testing"

	tpb "google3/google/protobuf/timestamp_go_proto"
	pmpb "google3/privacy/net/common/proto/public_metadata_go_proto"
)

func TestRoundTrip(t *testing.T) {
	bs := New(&NewBinaryFields{
		Version:     0,
		Country:     "US",
		Region:      "US-CA",
		City:        "SUNNYVALE",
		ServiceType: "chromeipblinding",
		Expiration:  &tpb.Timestamp{Seconds: 3600},
		DebugMode:   pmpb.PublicMetadata_DEBUG_ALL,
	})
	serialized, err := Serialize(bs)
	if err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}
	deserialized, err := Deserialize(serialized)
	if err != nil {
		t.Fatalf("Deserialize failed: %v", err)
	}
	if bs.GetServiceType() != deserialized.GetServiceType() {
		t.Errorf("service_type: got %v; want %v", deserialized.GetServiceType(), bs.GetServiceType())
	}
	if bs.GetExpiration().GetSeconds() != deserialized.GetExpiration().GetSeconds() {
		t.Errorf("expiration: got %v; want %v", deserialized.GetExpiration().GetSeconds(), bs.GetExpiration().GetSeconds())
	}
	if bs.GetDebugMode() != deserialized.GetDebugMode() {
		t.Errorf("debug_mode: got %v; want %v", deserialized.GetDebugMode(), bs.GetDebugMode())
	}
	if bs.GetExitLocation().GetCountry() != deserialized.GetExitLocation().GetCountry() {
		t.Errorf("country: got %v; want %v", deserialized.GetExitLocation().GetCountry(), bs.GetExitLocation().GetCountry())
	}
	if bs.metadata.GetRegion().Value() != deserialized.metadata.GetRegion().Value() {
		t.Errorf("region: got %q; want %q", deserialized.metadata.GetRegion().Value(), bs.metadata.GetRegion().Value())
	}
	if bs.metadata.GetCity().Value() != deserialized.metadata.GetCity().Value() {
		t.Errorf("city: got %q; want %q", deserialized.metadata.GetCity().Value(), bs.metadata.GetCity().Value())
	}
}
