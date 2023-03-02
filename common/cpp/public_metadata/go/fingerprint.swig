%include "base/swig/google.swig"
%include "net/proto/swig/go/protofunc.swig"

%{
#include "privacy/net/common/cpp/public_metadata/fingerprint.h"
%}

PROTO_INPUT(privacy::ppn::PublicMetadata,
            pmpb "google3/privacy/net/common/proto/public_metadata_go_proto",
            pmpb.PublicMetadata);

%ignoreall
%unignore privacy;
%unignore privacy::ppn;
%unignore privacy::ppn::FingerprintPublicMetadata(const privacy::ppn::PublicMetadata&, uint64_t*);
%include "privacy/net/common/cpp/public_metadata/fingerprint.h"
%unignoreall
