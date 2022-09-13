// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
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

#ifndef PRIVACY_NET_KRYPTON_UTILS_PROTO_COMPARISON_H_
#define PRIVACY_NET_KRYPTON_UTILS_PROTO_COMPARISON_H_

#include "privacy/net/krypton/proto/tun_fd_data.proto.h"

namespace privacy {
namespace krypton {
namespace utils {

bool IpRangeEquiv(const TunFdData_IpRange&, const TunFdData_IpRange&);

bool TunFdDataEquiv(const TunFdData&, const TunFdData&);

}  // namespace utils
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_UTILS_PROTO_COMPARISON_H_
