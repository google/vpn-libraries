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
#include "privacy/net/krypton/jni/jni_cache.h"
#include "privacy/net/krypton/jni/jni_utils.h"
#include "privacy/net/krypton/proto/http_fetcher.proto.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/jsoncpp/value.h"
#include "third_party/jsoncpp/writer.h"

namespace privacy {
namespace krypton {
namespace jni {

HttpResponse HttpFetcher::PostJson(const HttpRequest& request) {
  LOG(INFO) << "Calling HttpFetcher JNI method to " << request.url();
  auto jni_ppn = JniCache::Get();
  auto env = jni_ppn->GetJavaEnv();
  if (!env) {
    HttpResponse response;
    response.mutable_status()->set_code(503);
    response.mutable_status()->set_message("Java Env is not found");
    return response;
  }

  std::string request_bytes;
  request.SerializeToString(&request_bytes);

  jbyteArray java_response_array =
      static_cast<jbyteArray>(env.value()->CallObjectMethod(
          jni_ppn->GetHttpFetcherObject(),
          jni_ppn->GetHttpFetcherPostJsonMethod(),
          JavaByteArray(env.value(), request_bytes).get()));

  HttpResponse response;

  // If Java returned null, then treat it as a 500 Internal error.
  if (java_response_array == nullptr) {
    response.mutable_status()->set_code(500);
    response.mutable_status()->set_message("empty response from java");
    return response;
  }

  // Try to parse the proto returned from Java.
  jsize len = env.value()->GetArrayLength(java_response_array);
  jbyte* bytes =
      env.value()->GetByteArrayElements(java_response_array, nullptr);
  if (!response.ParseFromArray(bytes, len)) {
    response.mutable_status()->set_code(500);
    response.mutable_status()->set_message("invalid proto response from java");
    return response;
  }
  env.value()->ReleaseByteArrayElements(java_response_array, bytes, 0);

  return response;
}

}  // namespace jni
}  // namespace krypton
}  // namespace privacy
