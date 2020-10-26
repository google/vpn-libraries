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

#include "privacy/net/krypton/jni/http_fetcher.h"

#include <jni.h>

#include <optional>
#include <string>

#include "base/logging.h"
#include "privacy/net/krypton/http_header.h"
#include "privacy/net/krypton/jni/jni_cache.h"
#include "privacy/net/krypton/jni/jni_utils.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/jsoncpp/value.h"
#include "third_party/jsoncpp/writer.h"

namespace privacy {
namespace krypton {
namespace jni {

std::string HttpFetcher::PostJson(absl::string_view url,
                                  const Json::Value& headers,
                                  const Json::Value& json_body) {
  LOG(INFO) << "Calling HttpFetcher JNI method to " << url;
  auto jni_ppn = JniCache::Get();
  auto env = jni_ppn->GetJavaEnv();
  if (!env) {
    return HttpResponse::BuildResponse(503, "Java Env is not found").asString();
  }

  Json::FastWriter writer;

  jstring java_response_string =
      static_cast<jstring>(env.value()->CallObjectMethod(
          jni_ppn->GetHttpFetcherObject(),
          jni_ppn->GetHttpFetcherPostJsonMethod(),
          JavaString(env.value(), std::string(url)).get(),
          headers.empty()
              ? nullptr
              : JavaString(env.value(), writer.write(headers)).get(),
          JavaString(env.value(), writer.write(json_body)).get()));

  if (java_response_string == nullptr) {
    return std::string();
  }
  return ConvertJavaStringToUTF8(env.value(), java_response_string);
}

}  // namespace jni
}  // namespace krypton
}  // namespace privacy
