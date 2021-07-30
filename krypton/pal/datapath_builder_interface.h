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

#ifndef PRIVACY_NET_KRYPTON_PAL_DATAPATH_BUILDER_INTERFACE_H_
#define PRIVACY_NET_KRYPTON_PAL_DATAPATH_BUILDER_INTERFACE_H_

#include "privacy/net/krypton/datapath_interface.h"
#include "privacy/net/krypton/proto/krypton_config.proto.h"
#include "privacy/net/krypton/utils/looper.h"

namespace privacy {
namespace krypton {

// An interface for a builder that can build a PacketPipe upon demand.
class DatapathBuilder {
 public:
  DatapathBuilder() = default;
  virtual ~DatapathBuilder() = default;

  // Builds a network-side pipe that reads and writes packets.
  virtual DatapathInterface* BuildDatapath(KryptonConfig* config,
                                           utils::LooperThread* looper) = 0;
};

}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_PAL_DATAPATH_BUILDER_INTERFACE_H_
