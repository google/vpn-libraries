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

#import "googlemac/iPhone/Shared/PPN/Classes/PPNDisconnectionStatus+Internal.h"

#import "googlemac/iPhone/Shared/PPN/API/PPNDisconnectionStatus.h"
#import "googlemac/iPhone/Shared/PPN/API/PPNError.h"
#import "privacy/net/krypton/proto/connection_status.proto.h"

@implementation PPNDisconnectionStatus

- (instancetype)initWithDisconnectionStatus:
    (const privacy::krypton::DisconnectionStatus &)disconnectionStatus {
  self = [super init];
  if (self != nullptr) {
    absl::Status reason(static_cast<absl::StatusCode>(disconnectionStatus.code()),
                        disconnectionStatus.message());
    _disconnectionReason = privacy::krypton::NSErrorFromPPNStatus(reason);
    _hasAvailableNetworks = disconnectionStatus.has_available_networks();
  }
  return self;
}

- (NSString *)description {
  return
      [[NSString alloc] initWithFormat:@"<%@: %p; disconnectionReason:%@ hasAvailableNetworks:%@>",
                                       NSStringFromClass([self class]), self, _disconnectionReason,
                                       _hasAvailableNetworks ? @"YES" : @"NO"];
}

@end
