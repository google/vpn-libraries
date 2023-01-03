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
#include "privacy/net/krypton/utils/json_util.h"
#include "third_party/json/include/nlohmann/json.hpp"

using privacy::krypton::windows::HttpFetcher;

int main(int argc, char* argv[]) {
  InitGoogle(argv[0], &argc, &argv, /*remove_flags=*/true);

  auto http_fetcher = std::make_unique<HttpFetcher>();

  auto resolved_address = http_fetcher->LookupDns("na.b.g-tun.com");
  if (!resolved_address.ok()) {
    LOG(ERROR) << "LookupDns failed: " << resolved_address.status();
    return 0;
  }
  LOG(INFO) << "Result of LookupDns: " << resolved_address.value();

  // PublicKey Request
  auto url = "https://staging.zinc.cloud.cupronickel.goog/publickey";

  privacy::krypton::HttpRequest request;
  nlohmann::json json_body;
  json_body["get_public_key"] = true;

  request.set_json_body(privacy::krypton::utils::JsonToString(json_body));
  request.set_url(url);

  auto http_response = http_fetcher->PostJson(request);
  LOG(INFO) << "Result of PostJson:";
  LOG(INFO) << "Status code: " << http_response.status().code();
  LOG(INFO) << "Status message: " << http_response.status().message();
  LOG(INFO) << "Json response: " << http_response.json_body();

  return 0;
}
