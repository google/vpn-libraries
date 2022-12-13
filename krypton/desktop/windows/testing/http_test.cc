// Copyright 2022 Google LLC
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

#include <string>
#include <utility>

#include "base/init_google.h"
#include "privacy/net/krypton/desktop/windows/http_fetcher.h"
#include "privacy/net/krypton/proto/http_fetcher.proto.h"
#include "third_party/absl/flags/flag.h"
#include "third_party/absl/memory/memory.h"

// A simple http fetcher for testing the http fetcher library.

ABSL_FLAG(std::string, addr, "http://localhost:12345/foo", "address");
ABSL_FLAG(std::string, body, "{\"text\":\"hello\"}", "json body");

using privacy::krypton::HttpRequest;
using privacy::krypton::windows::HttpFetcher;

int main(int argc, char* argv[]) {
  InitGoogle(argv[0], &argc, &argv, /*remove_flags=*/true);

  HttpFetcher http_fetcher;
  std::string addr = absl::GetFlag(FLAGS_addr);
  std::string body = absl::GetFlag(FLAGS_body);

  HttpRequest request;
  request.set_url(addr);
  request.set_json_body(body);

  auto response = http_fetcher.PostJson(request);
  LOG(INFO) << "response: " << response.DebugString();

  return 0;
}
