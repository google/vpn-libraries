// Package publicmetadata contains definitions for public metadata structs.
package publicmetadata

import (
	wrap "google3/privacy/net/common/cpp/public_metadata/go/wrap_public_metadata"
	pmpb "google3/privacy/net/common/proto/public_metadata_go_proto"
)

// BinaryStruct is a wrapper type for a C++ BinaryPublicMetadata struct.
type BinaryStruct struct {
	metadata wrap.BinaryPublicMetadata
}

// New returns a new BinaryStruct.
func New() *BinaryStruct {
	return &BinaryStruct{
		metadata: wrap.NewBinaryPublicMetadata(),
	}
}

// Free frees the memory of the wrapped C++ BinaryPublicMetadata struct.
func Free(bs *BinaryStruct) {
	wrap.DeleteBinaryPublicMetadata(bs.metadata)
	bs.metadata = nil
}

// Serialize converts a proto PublicMetadata into a BinaryPublicMetadata struct.
func Serialize(proto *pmpb.PublicMetadata) *BinaryStruct {
	return &BinaryStruct{
		metadata: wrap.PublicMetadataProtoToStruct(proto),
	}
}
