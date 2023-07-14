// Package binarymetadata contains definitions for public metadata structs.
package binarymetadata

import (
	tpb "google3/google/protobuf/timestamp_go_proto"
	wrap "google3/privacy/net/common/cpp/public_metadata/go/wrap_public_metadata"
	pmpb "google3/privacy/net/common/proto/public_metadata_go_proto"
)

// BinaryStruct is a wrapper type for a C++ BinaryPublicMetadata struct.
type BinaryStruct struct {
	metadata wrap.BinaryPublicMetadata
}

// GetExpiration gets expiration timestamp
func (bs *BinaryStruct) GetExpiration() *tpb.Timestamp {
	epoch := bs.metadata.GetExpiration_epoch_seconds()
	if epoch == nil || !epoch.HasValue() {
		return nil
	}
	s := int64(epoch.Value())
	return &tpb.Timestamp{Seconds: s}
}

// GetServiceType gets the service type
func (bs *BinaryStruct) GetServiceType() string {
	service := bs.metadata.GetService_type()
	if service == nil || !service.HasValue() {
		return ""
	}
	return service.Value()
}

// GetExitLocation converts the country, region, city into a Location struct
func (bs *BinaryStruct) GetExitLocation() *pmpb.PublicMetadata_Location {
	el := &pmpb.PublicMetadata_Location_builder{}
	country := bs.metadata.GetCountry()
	if country == nil || !country.HasValue() {
		return el.Build()
	}
	el.Country = country.Value()
	// TODO: b/285899811 - figure out how to reconcile external and internal representations of city
	// geos.
	return el.Build()
}

// GetDebugMode gets the debug mode
func (bs *BinaryStruct) GetDebugMode() pmpb.PublicMetadata_DebugMode {
	value := int32(bs.metadata.GetDebug_mode())
	if _, ok := pmpb.PublicMetadata_DebugMode_name[value]; !ok {
		return pmpb.PublicMetadata_UNSPECIFIED_DEBUG_MODE
	}
	return pmpb.PublicMetadata_DebugMode(value)
}

// NewBinaryFields contains all the data for creating a binary representation for public metadata.
type NewBinaryFields struct {
	Version     int32
	Loc         *pmpb.PublicMetadata_Location
	ServiceType string
	Expiration  *tpb.Timestamp
	DebugMode   pmpb.PublicMetadata_DebugMode
}

// New returns a new BinaryStruct.
func New(fields *NewBinaryFields) *BinaryStruct {
	metadata := wrap.NewBinaryPublicMetadata()
	metadata.SetVersion(uint(fields.Version))
	metadata.SetCountry(wrap.NewStringOptional(fields.Loc.GetCountry()))
	metadata.SetService_type(wrap.NewStringOptional(fields.ServiceType))
	metadata.SetExpiration_epoch_seconds(wrap.NewUint64Optional(uint64(fields.Expiration.GetSeconds())))
	metadata.SetDebug_mode(uint(fields.DebugMode.Number()))
	return &BinaryStruct{metadata}
}

// Free frees the memory of the wrapped C++ BinaryPublicMetadata struct.
func (bs *BinaryStruct) Free() {
	wrap.DeleteBinaryPublicMetadata(bs.metadata)
	bs.metadata = nil
}

// Serialize the binary public metadata to bytes in a string. When this call returns, the caller
// should ensure to call bs.Free()
func Serialize(bs *BinaryStruct) ([]byte, error) {
	return []byte(wrap.Serialize(bs.metadata)), nil
}

// Deserialize bytes to binary public metadata.
func Deserialize(in []byte) (*BinaryStruct, error) {
	md := wrap.Deserialize(string(in[:]))
	return &BinaryStruct{metadata: md}, nil
}
