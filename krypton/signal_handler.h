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


#ifndef PRIVACY_NET_KRYPTON_SIGNAL_HANDLER_H_
#define PRIVACY_NET_KRYPTON_SIGNAL_HANDLER_H_

#include <csignal>

#include "privacy/net/krypton/pal/krypton_notification_interface.h"

namespace privacy {
namespace krypton {

class SignalHandler {
 public:
  // Sets the interface to call back when a handled signal occurs.
  static void RegisterNotificationInterface(
      KryptonNotificationInterface* interface);

 private:
  // Installs our custom signal handlers to get notified of exceptions.
  static void Install();

  // Gets called whenever one of the handled signals is raised.
  static void OnSignal(int signal, siginfo_t* info, void* unused);
};

}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_SIGNAL_HANDLER_H_
