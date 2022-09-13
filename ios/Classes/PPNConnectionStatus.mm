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

#import "googlemac/iPhone/Shared/PPN/Classes/PPNConnectionStatus+Internal.h"

#import "googlemac/iPhone/Shared/PPN/API/PPNConnectionStatus.h"
#import "privacy/net/krypton/proto/connection_status.proto.h"

@implementation PPNConnectionStatus

- (instancetype)initWithConnectionStatus:
    (const privacy::krypton::ConnectionStatus &)connectionStatus {
  self = [super init];
  if (self != nullptr) {
    _networkType = PPNNetworkType(connectionStatus.network_type());
    _security = PPNSecurityType(connectionStatus.security());
    _quality = PPNConnectionQuality(connectionStatus.quality());
  }
  return self;
}

- (NSString *)description {
  return [[NSString alloc] initWithFormat:@"<%@: %p; networkType:%tu security:%tu quality:%tu>",
                                          NSStringFromClass([self class]), self, _networkType,
                                          _security, _quality];
}

@end
