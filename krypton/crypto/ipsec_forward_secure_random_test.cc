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

#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"

namespace privacy {
namespace krypton {
namespace crypto {
namespace {

class IpSecForwardSecureRandomTest : public ::testing::Test {};

TEST_F(IpSecForwardSecureRandomTest, TestRandString) {
  auto result = CreateSecureRandomString(8);
  EXPECT_EQ(result.size(), 8);

  std::set<char> chars;
  for (char it : result) {
    chars.insert(it);
  }
  ASSERT_GT(chars.size(), 1);
}

}  // namespace
}  // namespace crypto
}  // namespace krypton
}  // namespace privacy
