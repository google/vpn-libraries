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

#include "privacy/net/krypton/crypto/suite.h"

namespace privacy {
namespace krypton {

std::string CryptoSuiteName(CryptoSuite suite) {
  switch (suite) {
    case CryptoSuite::UNSPECIFIED:
      return "UNSPECIFIED";
    case CryptoSuite::AES128_GCM:
      return "AES128_GCM";
    case CryptoSuite::AES256_GCM:
      return "AES256_GCM";
  }
}

}  // namespace krypton
}  // namespace privacy
