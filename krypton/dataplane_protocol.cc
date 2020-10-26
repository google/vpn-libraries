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

#include "privacy/net/krypton/dataplane_protocol.h"

namespace privacy {
namespace krypton {

std::string DataplaneProtocolName(DataplaneProtocol protocol) {
  switch (protocol) {
    case DataplaneProtocol::UNSPECIFIED:
      return "UNSPECIFIED";
    case DataplaneProtocol::IPSEC:
      return "IPSEC";
    case DataplaneProtocol::BRIDGE:
      return "BRIDGE";
  }
}

}  // namespace krypton
}  // namespace privacy
