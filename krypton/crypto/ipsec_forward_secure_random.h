// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "LICENSE");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS-IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef PRIVACY_NET_KRYPTON_CRYPTO_IPSEC_FORWARD_SECURE_RANDOM_H_
#define PRIVACY_NET_KRYPTON_CRYPTO_IPSEC_FORWARD_SECURE_RANDOM_H_

#include <string>

namespace privacy {
namespace krypton {
namespace crypto {

// Returns a string of random bytes of a given desired length.
//
// This can be used to generate a string that will be served as IV.
std::string CreateSecureRandomString(const int desired_len);

}  // namespace crypto
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_CRYPTO_IPSEC_FORWARD_SECURE_RANDOM_H_
