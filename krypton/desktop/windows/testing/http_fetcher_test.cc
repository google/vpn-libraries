/*
 * Copyright (C) 2021 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "privacy/net/krypton/desktop/windows/http_fetcher.h"

#include <memory>

#include "base/init_google.h"
#include "privacy/net/common/proto/get_initial_data.proto.h"
#include "privacy/net/krypton/utils/json_util.h"
#include "third_party/absl/strings/str_cat.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/json/include/nlohmann/json.hpp"

using privacy::krypton::windows::HttpFetcher;
using privacy::ppn::GetInitialDataRequest;

ABSL_FLAG(std::string, oauth_token, "", "Valid OAuth token");

void TryPublicKeyRequest(HttpFetcher* http_fetcher) {
  // PublicKey Request
  auto url = "https://staging.zinc.cloud.cupronickel.goog/publickey";

  privacy::krypton::HttpRequest request;
  nlohmann::json json_body;
  json_body["get_public_key"] = true;

  request.set_json_body(privacy::krypton::utils::JsonToString(json_body));
  request.set_url(url);

  LOG(INFO) << "Requesting PublicKey.";
  auto http_response = http_fetcher->PostJson(request);
  LOG(INFO) << "Result of PostJson:";
  LOG(INFO) << "Status code: " << http_response.status().code();
  LOG(INFO) << "Status message: " << http_response.status().message();
  LOG(INFO) << "Json response: " << http_response.json_body();
}

void TryInitialDataRequest(HttpFetcher* http_fetcher,
                           absl::string_view oauth_token) {
  auto url =
      "https://autopush-phosphor-pa.sandbox.googleapis.com/v1/getInitialData";

  privacy::krypton::HttpRequest request;
  GetInitialDataRequest initial_data_request;
  initial_data_request.set_use_attestation(false);
  initial_data_request.set_service_type("g1");
  initial_data_request.set_location_granularity(
      privacy::ppn::GetInitialDataRequest::LocationGranularity(1));

  request.set_proto_body(initial_data_request.SerializeAsString());
  request.set_url(url);
  (*request.mutable_headers())["Authorization"] =
      absl::StrCat("Bearer ", oauth_token);

  LOG(INFO) << "Requesting GetInitialData.";
  auto http_response = http_fetcher->PostJson(request);
  auto initial_data_response = privacy::ppn::GetInitialDataResponse();
  initial_data_response.ParseFromString(http_response.proto_body());

  LOG(INFO) << "Result of PostJson:";
  LOG(INFO) << "Status code: " << http_response.status().code();
  LOG(INFO) << "Status message: " << http_response.status().message();
  LOG(INFO) << "Initial data response: " << initial_data_response;
}

int main(int argc, char* argv[]) {
  InitGoogle(argv[0], &argc, &argv, /*remove_flags=*/true);

  if (absl::GetFlag(FLAGS_oauth_token).empty()) {
    LOG(ERROR) << "Required flag missing: --oauth_token";
    return -1;
  }

  // go/ppn-windows-testing for example of how to obtain oauth token.
  auto oauth_token = absl::GetFlag(FLAGS_oauth_token);
  HttpFetcher http_fetcher;

  auto resolved_address = http_fetcher.LookupDns("na4.p.g-tun.com");
  if (!resolved_address.ok()) {
    LOG(ERROR) << "LookupDns failed: " << resolved_address.status();
    return 0;
  }
  LOG(INFO) << "Result of LookupDns: " << resolved_address.value();

  // PublicKey Request
  TryPublicKeyRequest(&http_fetcher);

  // GetInitialData Request
  TryInitialDataRequest(&http_fetcher, oauth_token);

  return 0;
}

