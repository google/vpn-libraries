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

#include "privacy/net/krypton/crypto/ipsec_forward_secure_random.h"

#include "base/logging.h"
#include "third_party/tink/cc/subtle/random.h"

namespace privacy {
namespace krypton {
namespace crypto {

std::string CreateSecureRandomString(int desired_len) {
  CHECK_GE(desired_len, 0);
  std::string result;
  result.resize(desired_len);
  for (char& it : result) {
    it = ::crypto::tink::subtle::Random::GetRandomUInt8();
  }
  return result;
}

}  // namespace crypto
}  // namespace krypton
}  // namespace privacy
