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

#ifndef PRIVACY_NET_KRYPTON_JNI_DATAPATH_BUILDER_H_
#define PRIVACY_NET_KRYPTON_JNI_DATAPATH_BUILDER_H_

#include "privacy/net/krypton/pal/datapath_builder_interface.h"
#include "privacy/net/krypton/pal/vpn_service_interface.h"

namespace privacy {
namespace krypton {
namespace jni {

// JNI implementation for the DatapathBuilder.
class DatapathBuilderImpl : public DatapathBuilder {
 public:
  explicit DatapathBuilderImpl(VpnServiceInterface* vpn_service)
      : vpn_service_(vpn_service) {}
  // Returns a datapath based on the `config`.
  DatapathInterface* BuildDatapath(KryptonConfig* config,
                                   utils::LooperThread* looper) override;

 private:
  VpnServiceInterface* vpn_service_;  // Not owned.
};

}  // namespace jni
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_JNI_DATAPATH_BUILDER_H_
