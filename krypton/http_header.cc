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

#include "privacy/net/krypton/http_header.h"

#include <map>
#include <string>
#include <utility>

#include "privacy/net/krypton/json_keys.h"
#include "third_party/absl/memory/memory.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/absl/types/optional.h"
#include "third_party/jsoncpp/value.h"

namespace privacy {
namespace krypton {

void HttpHeader::AddHeader(absl::string_view header, absl::string_view value) {
  headers_[std::string(header)] = std::string(value);
}

absl::Status HttpHeader::DecodeFromJsonObject(Json::Value value) {
  for (auto it = value.begin(); it != value.end(); ++it) {
    headers_[it.name()] = (*it).asString();
  }
  return absl::OkStatus();
}

absl::StatusOr<std::string> HttpHeader::GetHeader(
    absl::string_view header_name) const {
  const auto it = headers_.find(std::string(header_name));
  if (it == headers_.end()) {
    return absl::NotFoundError("Not found");
  }
  return it->second;
}

absl::optional<Json::Value> HttpHeader::EncodeToJsonObject() const {
  if (headers_.empty()) {
    return absl::nullopt;
  }
  Json::Value header_name_values;

  for (const auto& it : headers_) {
    header_name_values[it.first] = it.second;
  }
  return header_name_values;
}

absl::optional<Json::Value> HttpRequest::EncodeToJsonObject() const {
  Json::Value http_header;
  auto json_headers = header_.EncodeToJsonObject();
  if (!json_headers) {
    return absl::nullopt;
  }
  http_header[JsonKeys::kHeadersKey] = json_headers.value();
  return http_header;
}

absl::Status HttpResponse::DecodeFromJsonObject(Json::Value status) {
  // Response is in this format.
  //
  // {
  //   "status": {
  //     "code": 200,
  //     "message" : "OK"
  //.  }
  //   "headers" : {
  //      "some_header_name" : "some_value"
  //    }
  // }
  // Get the status field.
  if (status.isMember(JsonKeys::kStatusCodeKey)) {
    status_ = status[JsonKeys::kStatusCodeKey].asInt();
  } else {
    return absl::InvalidArgumentError("No Status found in the response");
  }

  if (status.isMember(JsonKeys::kMessageKey)) {
    message_ = status[JsonKeys::kMessageKey].asString();
  }

  return absl::OkStatus();
}

Json::Value HttpResponse::BuildResponse(int status, absl::string_view message) {
  Json::Value http;
  http[JsonKeys::kStatusCodeKey] = status;
  http[JsonKeys::kMessageKey] = std::string(message);
  return http;
}

}  // namespace krypton
}  // namespace privacy
