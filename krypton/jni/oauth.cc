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

#include "privacy/net/krypton/jni/oauth.h"

#include <jni.h>

#include <optional>
#include <string>

#include "base/logging.h"
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

  jobject token_jobject =
      env.value()->CallObjectMethod(jni_cache->GetKryptonObject(),
                                    jni_cache->GetKryptonGetOAuthTokenMethod());

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

}  // namespace jni
}  // namespace krypton
}  // namespace privacy
