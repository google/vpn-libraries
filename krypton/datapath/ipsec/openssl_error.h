// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the );
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an  BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef PRIVACY_NET_KRYPTON_DATAPATH_IPSEC_OPENSSL_ERROR_H_
#define PRIVACY_NET_KRYPTON_DATAPATH_IPSEC_OPENSSL_ERROR_H_

#include "third_party/absl/status/status.h"
#include "third_party/absl/strings/string_view.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace ipsec {

// Gets a Status representing any OpenSSL errors currently on its error stack.
absl::Status GetOpenSSLError(absl::string_view prefix);

}  // namespace ipsec
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DATAPATH_IPSEC_OPENSSL_ERROR_H_
