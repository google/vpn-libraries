// Copyright 2021 Google LLC
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

#ifndef PRIVACY_NET_KRYPTON_DATAPATH_UTILS_UTILS_H_
#define PRIVACY_NET_KRYPTON_DATAPATH_UTILS_UTILS_H_

#include "third_party/absl/strings/string_view.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace utils {

// Given a binary buffer, return a hex+ASCII dump in the style of
// tcpdump's -X and -XX options:
// "0x0000:  0090 69bd 5400 000d 610f 0189 0800 4500  ..i.T...a.....E.\n"
// "0x0010:  001c fb98 4000 4001 7e18 d8ef 2301 455d  ....@.@.~...#.E]\n"
// "0x0020:  7fe2 0800 6bcb 0bc6 806e                 ....k....n\n"
std::string StringToHexASCIIDump(absl::string_view in_buffer);

}  // namespace utils
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DATAPATH_UTILS_UTILS_H_
