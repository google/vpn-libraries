// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef PRIVACY_NET_KRYPTON_JNI_OAUTH_H_
#define PRIVACY_NET_KRYPTON_JNI_OAUTH_H_

#include <jni.h>

#include <memory>
#include <string>

#include "base/logging.h"
#include "privacy/net/attestation/proto/attestation.proto.h"
#include "privacy/net/krypton/jni/jni_cache.h"
#include "privacy/net/krypton/pal/oauth_interface.h"
#include "third_party/absl/status/statusor.h"

namespace privacy {
namespace krypton {
namespace jni {

class OAuth : public OAuthInterface {
 public:
  explicit OAuth(jobject oauth_token_provider_instance)
      : oauth_token_provider_instance_(
            std::make_unique<JavaObject>(oauth_token_provider_instance)) {}
  ~OAuth() override = default;

  absl::StatusOr<std::string> GetOAuthToken() override;

  absl::StatusOr<privacy::ppn::AttestationData> GetAttestationData(
      const std::string& nonce) override;

 private:
  std::unique_ptr<JavaObject> oauth_token_provider_instance_;
};

}  // namespace jni
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_JNI_OAUTH_H_
