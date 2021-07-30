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

#include "privacy/net/krypton/jni/datapath_builder.h"

#include "privacy/net/krypton/datapath/android_ipsec/ipsec_datapath.h"


namespace privacy {
namespace krypton {
namespace jni {

DatapathInterface* DatapathBuilderImpl::BuildDatapath(
    KryptonConfig* config, utils::LooperThread* looper) {
  if (config->datapath_protocol() == KryptonConfig::IPSEC) {
    return new datapath::android::IpSecDatapath(looper, vpn_service_);
  }
}

}  // namespace jni
}  // namespace krypton
}  // namespace privacy
