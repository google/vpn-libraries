/*
 * Copyright (C) 2021 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_MOCK_WINTUN_H_
#define PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_MOCK_WINTUN_H_

#include "privacy/net/krypton/desktop/window/wintun_interface.h"
#include "testing/base/public/gmock.h"

namespace privacy {
namespace krypton {
namespace windows {

class MockWintun {
  MOCK_METHOD(absl::Status, CreateAdapter,
              (absl::string_view, absl::string_view), (override));

  MOCK_METHOD(absl::Status, CloseAdapter, (), (override));

  MOCK_METHOD(uint32_t, GetRunningDriverVersion, (), (override));

  MOCK_METHOD(absl::StatusOr<NET_LUID>, GetAdapterLUID, (), (override));

  MOCK_METHOD(absl::Status, StartSession, (), (override));

  MOCK_METHOD(absl::Status, EndSession, (), (override));

  MOCK_METHOD(HANDLE, GetWaitReadEvent, (), (override));

  MOCK_METHOD(absl::StatusOr<Packet>, AllocateSendPacket, (uint32_t),
              (override));

  MOCK_METHOD(absl::Status, SendPacket, (Packet), (override));

  MOCK_METHOD(absl::StatusOr<Packet>, ReceivePacket, (), (override));

  MOCK_METHOD(absl::Status, ReleaseReceivePacket, (Packet), (override));
};

}  // namespace windows
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_MOCK_WINTUN_H_
