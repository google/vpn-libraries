// Copyright 2020 Google LLC
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

#ifndef PRIVACY_NET_KRYPTON_JNI_OAUTH_H_
#define PRIVACY_NET_KRYPTON_JNI_OAUTH_H_

#include <string>

#include "privacy/net/krypton/pal/oauth_interface.h"
#include "third_party/absl/status/statusor.h"

namespace privacy {
namespace krypton {
namespace jni {

class OAuth : public OAuthInterface {
 public:
  OAuth() = default;
  ~OAuth() override = default;

  absl::StatusOr<std::string> GetOAuthToken() override;
};

}  // namespace jni
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_JNI_OAUTH_H_
