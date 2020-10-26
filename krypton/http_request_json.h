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

#ifndef PRIVACY_NET_KRYPTON_HTTP_REQUEST_JSON_H_
#define PRIVACY_NET_KRYPTON_HTTP_REQUEST_JSON_H_

#include "third_party/jsoncpp/value.h"

namespace privacy {
namespace krypton {

// Struct used for returning the constructed server requests split by http
// headers and json_body.
struct HttpRequestJson {
  HttpRequestJson(Json::Value headers, Json::Value body)
      : http_headers(headers), json_body(body) {}
  Json::Value http_headers;
  Json::Value json_body;
};

}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_HTTP_REQUEST_JSON_H_
