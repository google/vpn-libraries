// We are wrapping the BinaryPublicMetadata struct and a function to serialize
// PublicMetadata protos into structs.

%include "base/swig/google.swig"
%include "net/proto/swig/go/protofunc.swig"
%include "strings/strings.swig"
%import "util/task/go/status.swig"

%{
#include "privacy/net/common/cpp/public_metadata/public_metadata.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/anonymous_tokens/cpp/privacy_pass/token_encodings.h"
#include "util/task/status.h"
#include "util/task/status.proto.h"
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

%include "privacy/net/common/cpp/public_metadata/public_metadata.h"
%unignoreall

%inline %{
struct StatusOrExtensionsString {
  absl::Status status;
  std::string extensions_str;
};

StatusOrExtensionsString SerializeExtensionsWrapped(privacy::ppn::BinaryPublicMetadata& metadata) {
  auto statusor = privacy::ppn::Serialize(metadata);
  StatusOrExtensionsString resp;
  resp.status = statusor.status();
  if (statusor.ok()) {
    resp.extensions_str = statusor.value();
  }
  return resp;
}

struct StatusOrExtensions {
  absl::Status status;
  privacy::ppn::BinaryPublicMetadata extensions;
};

StatusOrExtensions DeserializeExtensionsWrapped(std::string extensions_str) {
  auto statusor = privacy::ppn::Deserialize(extensions_str);
  StatusOrExtensions resp;
  resp.status = statusor.status();
  if (statusor.ok()) {
    resp.extensions = statusor.value();
  }
  return resp;
}
%}

