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

#include "privacy/net/common/cpp/public_metadata/serialize.h"

#include <cstdint>
#include <string>
#include <vector>

#include "testing/base/public/gunit.h"
#include "testing/fuzzing/fuzztest.h"
#include "third_party/absl/types/span.h"

namespace {

using privacy::ppn::BytesToUint64;
using privacy::ppn::Uint64ToBytes;

void TestUint64ToKeyAndBack(absl::Span<const uint64_t> input) {
  std::vector<uint64_t> vals;
  std::vector<std::string> keys;
  for (const uint64_t u64 : input) {
    vals.push_back(u64);
    keys.push_back(Uint64ToBytes(u64));
  }
  ASSERT_EQ(vals.size(), keys.size());
  for (int i = 0; i < vals.size(); i++) {
    EXPECT_EQ(BytesToUint64(keys[i]), vals[i]);
    EXPECT_EQ(BytesToUint64(Uint64ToBytes(vals[i])), vals[i]);
  }
}
FUZZ_TEST(FuzzKeyFromUint64, TestUint64ToKeyAndBack)
    .WithDomains(fuzztest::Arbitrary<std::vector<uint64_t>>().WithMinSize(32));

}  // namespace
