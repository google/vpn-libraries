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

#include "privacy/net/krypton/jni/oauth.h"

#include <jni.h>

#include <optional>
#include <string>

#include "base/logging.h"
#include "privacy/net/attestation/proto/attestation.proto.h"
#include "privacy/net/krypton/jni/jni_cache.h"
#include "privacy/net/krypton/jni/jni_utils.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"

namespace privacy {
namespace krypton {
namespace jni {

absl::StatusOr<std::string> OAuth::GetOAuthToken() {
  LOG(INFO) << "Requesting Zinc oauth token from Java";

  auto jni_cache = JniCache::Get();
  auto env = jni_cache->GetJavaEnv();
  if (!env) {
    LOG(ERROR) << "Cannot find JavaEnv to request zinc oauth token";
    return absl::Status(absl::StatusCode::kInternal, "Unable to get Java Env");
  }

  jobject token_jobject = env.value()->CallObjectMethod(
      oauth_token_provider_instance_->get(),
      jni_cache->GetOAuthTokenProviderGetOAuthTokenMethod());

  if (token_jobject == nullptr) {
    return absl::Status(absl::StatusCode::kUnavailable,
                        std::string("Unable to get zinc oauth token"));
  }

  jstring token_jstring = static_cast<jstring>(token_jobject);

  std::string token = ConvertJavaStringToUTF8(env.value(), token_jstring);

  if (token.empty()) {
    return absl::Status(absl::StatusCode::kUnavailable,
                        std::string("Unable to get zinc oauth token"));
  }
  return token;
}

absl::StatusOr<privacy::ppn::AttestationData> OAuth::GetAttestationData(
    const std::string& nonce) {
  LOG(INFO) << "Requesting Android attestation data from Java";

  auto jni_cache = JniCache::Get();
  auto env = jni_cache->GetJavaEnv();
  if (!env) {
    LOG(ERROR) << "Cannot find Java env to request attestation data";
    return absl::Status(absl::StatusCode::kInternal, "Unable to get Java Env");
  }

  jobject data_jobject = env.value()->CallObjectMethod(
      oauth_token_provider_instance_->get(),
      jni_cache->GetOAuthTokenProviderGetAttestationDataMethod(),
      JavaString(env.value(), nonce).get());

  if (data_jobject == nullptr) {
    return absl::Status(
        absl::StatusCode::kUnavailable,
        "Unable to get attestation data: failed to call GetAttestationData()");
  }
  jbyteArray data_jarray = static_cast<jbyteArray>(data_jobject);

  std::string data = ConvertJavaByteArrayToString(env.value(), data_jarray);
  if (data.empty()) {
    return absl::Status(
        absl::StatusCode::kUnavailable,
        "Unable to get attestation data: failed to serialize attestation data");
  }

  privacy::ppn::AttestationData proto;
  if (!proto.ParseFromString(data)) {
    return absl::InternalError("Unable to parse AttestationData.");
  }
  return proto;
}

}  // namespace jni
}  // namespace krypton
}  // namespace privacy
