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

/// Utility methods that convert a proto into a NSDictionary.

#import <Foundation/Foundation.h>

#include "google/protobuf/duration.proto.h"
#include "privacy/net/krypton/proto/debug_info.proto.h"
#include "privacy/net/krypton/proto/krypton_config.proto.h"
#include "privacy/net/krypton/proto/network_info.proto.h"
#include "privacy/net/krypton/proto/network_type.proto.h"

NSDictionary<NSString*, id>* PPNKryptonDebugInfoToNSDictionary(
    const privacy::krypton::KryptonDebugInfo& debugInfo);

NSDictionary<NSString*, id>* PPNKryptonConfigToNSDictionary(
    const privacy::krypton::KryptonConfig& config);

NSDictionary<NSString*, id>* PPNReconnectorConfigToNSDictionary(
    const privacy::krypton::ReconnectorConfig& config);

NSDictionary<NSString*, id>* PPNReconnectorDebugInfoToNSDictionary(
    const privacy::krypton::ReconnectorDebugInfo& debugInfo);

NSDictionary<NSString*, id>* PPNAuthDebugInfoToNSDictionary(
    const privacy::krypton::AuthDebugInfo& debugInfo);

NSDictionary<NSString*, id>* PPNEgressDebugInfoToNSDictionary(
    const privacy::krypton::EgressDebugInfo& debugInfo);

NSDictionary<NSString*, id>* PPNNetworkInfoToNSDictionary(
    const privacy::krypton::NetworkInfo& networkInfo);

NSDictionary<NSString*, id>* PPNSessionDebugInfoToNSDictionary(
    const privacy::krypton::SessionDebugInfo& debugInfo);

inline NSTimeInterval PPNDurationToNSTimeInterval(const ::google::protobuf::Duration& duration) {
  return (double)duration.seconds() + duration.nanos() * 0.000000001;
}
