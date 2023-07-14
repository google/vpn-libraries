// We are wrapping the BinaryPublicMetadata struct and a function to serialize
// PublicMetadata protos into structs.

%include "base/swig/google.swig"
%include "net/proto/swig/go/protofunc.swig"
%include "strings/strings.swig"

%{
#include "privacy/net/common/cpp/public_metadata/public_metadata.h"
%}

PROTO_INPUT(privacy::ppn::PublicMetadata,
            pmpb "google3/privacy/net/common/proto/public_metadata_go_proto",
            pmpb.PublicMetadata);
OPTIONAL_TYPEMAP(std::string, string, string, StringOptional)
OPTIONAL_TYPEMAP(uint64_t, uint64, uint64, Uint64Optional)

%ignoreall
%unignore privacy;
%unignore privacy::ppn;

%unignore privacy::ppn::BinaryPublicMetadata;
%unignore privacy::ppn::BinaryPublicMetadata::version;
%unignore privacy::ppn::BinaryPublicMetadata::service_type;
%unignore privacy::ppn::BinaryPublicMetadata::country;
%unignore privacy::ppn::BinaryPublicMetadata::region;
%unignore privacy::ppn::BinaryPublicMetadata::city;
%unignore privacy::ppn::BinaryPublicMetadata::expiration_epoch_seconds;
%unignore privacy::ppn::BinaryPublicMetadata::debug_mode;

%unignore privacy::ppn::PublicMetadataProtoToStruct(const privacy::ppn::PublicMetadata&);

%unignore privacy::ppn::Serialize(const privacy::ppn::BinaryPublicMetadata&);
%unignore privacy::ppn::Deserialize(absl::string_view);

%include "privacy/net/common/cpp/public_metadata/public_metadata.h"
%unignoreall
