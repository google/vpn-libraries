package binarymetadata

import (
	"errors"
	"testing"
	"time"

	"google3/util/task/go/status"

	tpb "google3/google/protobuf/timestamp_go_proto"
	plpb "google3/privacy/net/common/proto/proxy_layer_go_proto"
	pmpb "google3/privacy/net/common/proto/public_metadata_go_proto"
)

func TestValidateMetadataCardinality(t *testing.T) {
	bs := New(&NewBinaryFields{
		Version:     1,
		Country:     "US",
		Region:      "US-CA",
		City:        "SUNNYVALE",
		ServiceType: "chromeipblinding",
		Expiration:  tpb.New(time.Now().Add(time.Minute * 30).Round(time.Minute * 15)),
		DebugMode:   pmpb.PublicMetadata_DEBUG_ALL,
	})
	serialized, err := Serialize(bs)
	if err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}
	tests := []struct {
		name    string
		in      []byte
		t       time.Time
		wantErr error
	}{
		{
			name: "success",
			in:   serialized,
			t:    time.Now(),
		},
		{
			name:    "expiry",
			in:      serialized,
			t:       time.Unix(0, 0),
			wantErr: status.ErrInvalidArgument,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotErr := ValidateMetadataCardinality(tc.in, tc.t)
			if !errors.Is(gotErr, tc.wantErr) {
				t.Errorf("ValidateMetadataCardinality() returned error: %v, want error: %v", gotErr, tc.wantErr)
			}
		})
	}
}

func TestRoundTripV1(t *testing.T) {
	bs := New(&NewBinaryFields{
		Version:     1,
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
	if bs.GetProxyLayer() != deserialized.GetProxyLayer() {
		t.Errorf("proxy_layer: got %v; want %v", deserialized.GetProxyLayer(), bs.GetProxyLayer())
	}
}

func TestRoundTripV2(t *testing.T) {
	bs := New(&NewBinaryFields{
		Version:     2,
		Country:     "US",
		Region:      "US-CA",
		City:        "SUNNYVALE",
		ServiceType: "chromeipblinding",
		Expiration:  &tpb.Timestamp{Seconds: 3600},
		DebugMode:   pmpb.PublicMetadata_DEBUG_ALL,
		ProxyLayer:  plpb.ProxyLayer_PROXY_B,
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
	if bs.GetProxyLayer() != deserialized.GetProxyLayer() {
		t.Errorf("proxy_layer: got %v; want %v", deserialized.GetProxyLayer(), bs.GetProxyLayer())
	}
}
