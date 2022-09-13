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

#import "googlemac/iPhone/Shared/PPN/Classes/PPNNetworkInfo.h"

#import "googlemac/iPhone/Shared/PPN/API/PPNNetworkType.h"
#import "privacy/net/krypton/proto/network_info.proto.h"

@implementation PPNNetworkInfo

- (instancetype)initWithNetworkInfo:(const privacy::krypton::NetworkInfo &)networkInfo {
  self = [super init];
  if (self != nullptr) {
    _networkType = PPNNetworkType(networkInfo.network_type());
    _metered = networkInfo.is_metered();
    _addressFamily = PPNAddressFamily(networkInfo.address_family());
    _MTU = networkInfo.mtu();
    _networkID = networkInfo.network_id();
  }
  return self;
}

- (NSString *)description {
  return [[NSString alloc]
      initWithFormat:
          @"<%@: %p; networkType:%tu metered:%d addressFamily:%tu MTU:%d networkID:%lld>",
          NSStringFromClass([self class]), self, _networkType, (int)_metered, _addressFamily, _MTU,
          _networkID];
}

@end
