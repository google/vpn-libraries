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

#ifndef PRIVACY_NET_KRYPTON_AUTH_MESSAGES_H_
#define PRIVACY_NET_KRYPTON_AUTH_MESSAGES_H_

// Messages that are sent to the Authentication module or task.
namespace privacy {
namespace krypton {

// Used to wake up the queue that is blocked to have a clean exit.
// TODO: There should be a better way than this.

class EmptyMessage {
 public:
  EmptyMessage() = default;
  ~EmptyMessage() = default;
};

class Authenticate {
 public:
  Authenticate() = default;
  ~Authenticate() = default;
};

class Reauthenticate {
 public:
  Reauthenticate() = default;
  ~Reauthenticate() = default;
};

}  // namespace krypton
}  // namespace privacy
#endif  // PRIVACY_NET_KRYPTON_AUTH_MESSAGES_H_
