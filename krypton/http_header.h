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

#ifndef PRIVACY_NET_KRYPTON_HTTP_HEADER_H_
#define PRIVACY_NET_KRYPTON_HTTP_HEADER_H_

#include <map>
#include <string>

#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/absl/types/optional.h"
#include "third_party/jsoncpp/value.h"
#include "third_party/jsoncpp/writer.h"

namespace privacy {
namespace krypton {

// HttpHeaders
class HttpHeader {
 public:
  HttpHeader() = default;
  ~HttpHeader() = default;

  // Add a header.
  void AddHeader(absl::string_view header, absl::string_view value);
  // Returns the JSON Value.
  absl::optional<Json::Value> EncodeToJsonObject() const;

  // Parse the jSON values into appropriate headers.
  absl::Status DecodeFromJsonObject(Json::Value value);

  // Returns Header value for a given header.  Returns empty string if none
  // exists.
  absl::StatusOr<std::string> GetHeader(absl::string_view header_name) const;

 private:
  std::map<std::string, std::string> headers_;
};

// HttpRequest
class HttpRequest {
 public:
  HttpRequest() = default;
  ~HttpRequest() = default;
  absl::optional<Json::Value> EncodeToJsonObject() const;

  // Get for Headers
  const HttpHeader& header() const { return header_; }
  HttpHeader* MutableHeader() { return &header_; }

 private:
  HttpHeader header_;
};

// Http Response.
class HttpResponse {
 public:
  HttpResponse() = default;
  ~HttpResponse() = default;

  // Parse the JSON value containing the headers and populate the internal
  // structures.
  // Use isValid() to check the validity
  absl::Status DecodeFromJsonObject(Json::Value status);

  // Get for Headers
  const HttpHeader& header() const { return header_; }
  HttpHeader* MutableHeader() { return &header_; }

  bool is_successful() const { return status_ == 200; }

  // Get methods for Status.
  int status() const { return status_; }
  std::string message() const { return message_; }

  // Utility method for constructing a response.
  static Json::Value BuildResponse(int status, absl::string_view message);

 private:
  int status_;
  std::string message_;
  HttpHeader header_;
};
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_HTTP_HEADER_H_
