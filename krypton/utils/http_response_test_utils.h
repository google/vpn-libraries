// Copyright 2023 Google LLC
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

#ifndef PRIVACY_NET_KRYPTON_UTILS_HTTP_RESPONSE_TEST_UTILS_H_
#define PRIVACY_NET_KRYPTON_UTILS_HTTP_RESPONSE_TEST_UTILS_H_

#include "privacy/net/krypton/proto/http_fetcher.proto.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/anonymous_tokens/proto/anonymous_tokens.proto.h"
#include "third_party/openssl/base.h"

// This file is meant for utility functions related to the creation of fake
// HttpResponses that will allow testers to mock responses from the backend.
namespace privacy {
namespace krypton {
namespace utils {

HttpResponse CreateHttpResponseWithStatus(int status_code,
                                          absl::string_view status_message);

HttpResponse CreateGetInitialDataHttpResponse(
    const ::private_membership::anonymous_tokens::RSABlindSignaturePublicKey&
        public_key);

HttpResponse CreateAuthHttpResponse(
    const HttpRequest& auth_request, RSA* rsa_key,
    absl::string_view control_plane_hostname = "");

// Creates an AddEgressHttpResponse according to the data plane protocol in the
// request.
HttpResponse CreateAddEgressHttpResponse(const HttpRequest& add_egress_request);

// Creates an AddEgressHttpResponse for an IKE session.
HttpResponse CreateAddEgressHttpResponseForIke();

// Creates an AddEgressHttpResponse for a non-IKE session.
HttpResponse CreateAddEgressHttpResponseForNonIke();

// Creates an AddEgressHttpResponse for a rekey operation. Rekey only applies to
// non-IKE sessions.
HttpResponse CreateRekeyHttpResponse();

}  // namespace utils
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_UTILS_HTTP_RESPONSE_TEST_UTILS_H_
