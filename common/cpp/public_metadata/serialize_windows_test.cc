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

#include <cstdint>
#include <string>
#include <vector>

#include "base/init_google.h"
#include "base/logging.h"
#include "privacy/net/common/cpp/public_metadata/serialize.h"

using privacy::ppn::BytesToUint64;
using privacy::ppn::Uint64ToBytes;

int main(int argc, char* argv[]) {
  InitGoogle(argv[0], &argc, &argv, /*remove_flags=*/true);

  const std::vector<uint64_t> input{0x0102030405060708ull};

  std::vector<uint64_t> vals;
  std::vector<std::string> keys;
  for (const uint64_t u64 : input) {
    vals.push_back(u64);
    keys.push_back(Uint64ToBytes(u64));
  }
  LOG(INFO) << "Vals size: " << vals.size() << ", keys size: " << keys.size();
  for (int i = 0; i < vals.size(); i++) {
    LOG(INFO) << "BytesToUint64(key[" << i << "]) equals val[" << i
              << "]: " << (BytesToUint64(keys[i]) == vals[i]);
    LOG(INFO) << "BytesToUint64(Uint64ToBytes(val[" << i << "])) equals val["
              << i
              << "]: " << (BytesToUint64(Uint64ToBytes(vals[i])) == vals[i]);
  }

  return 0;
}
