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

#ifndef PRIVACY_NET_KRYPTON_DATAPLANE_PROTOCOL_H_
#define PRIVACY_NET_KRYPTON_DATAPLANE_PROTOCOL_H_

#include <string>

namespace privacy {
namespace krypton {

enum class DataplaneProtocol {
  UNSPECIFIED = 0,
  IPSEC = 1,
  BRIDGE = 2,  // deprecated
};

std::string DataplaneProtocolName(DataplaneProtocol protocol);

}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DATAPLANE_PROTOCOL_H_
