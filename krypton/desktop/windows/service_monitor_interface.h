/*
 * Copyright (C) 2022 Google Inc.
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

#ifndef PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_SERVICE_MONITOR_INTERFACE_H_
#define PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_SERVICE_MONITOR_INTERFACE_H_

namespace privacy {
namespace krypton {
namespace windows {

// Listener class for service status.
class ServiceMonitorInterface {
 public:
  ServiceMonitorInterface() = default;
  virtual ~ServiceMonitorInterface() = default;

  virtual void ServiceStopped() = 0;
};

}  // namespace windows
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DESKTOP_WINDOWS_SERVICE_MONITOR_INTERFACE_H_
