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

#include <string>

#import "googlemac/iPhone/Shared/PPN/API/PPNOptions.h"

#import "google/protobuf/duration.proto.h"
#import "googlemac/iPhone/Shared/PPN/Classes/PPNOptions+Internal.h"

#include "privacy/net/common/proto/ppn_options.proto.h"
#include "privacy/net/krypton/proto/krypton_config.proto.h"

#pragma mark - Required Options

PPNOptionKey const PPNOptionZincURLString = @"zincURL";

PPNOptionKey const PPNOptionZincPublicSigningKeyURLString = @"zincPublicSigningKeyURL";

PPNOptionKey const PPNOptionZincServiceType = @"zincServiceType";

PPNOptionKey const PPNOptionBrassURLString = @"brassURL";

PPNOptionKey const PPNOptionInitialDataURLString = @"initialDataURL";

PPNOptionKey const PPNPeriodicHealthCheckEnabled = @"periodicHealthCheckEnabled";

PPNOptionKey const PPNPeriodicHealthCheckDuration = @"periodicHealthCheckDuration";

PPNOptionKey const PPNIPv6Enabled = @"IPv6Enabled";

PPNOptionKey const PPNOptionCrashDebugLoggingEnabled = @"crashDebugLoggingEnabled";

PPNOptionKey const PPNPublicMetadataEnabled = @"publicMetadataEnabled";

#pragma mark - Optional Options

PPNOptionKey const PPNOptionZincOAuthScope = @"zincOAuthScope";

PPNOptionKey const PPNOptionCopperControllerAddress = @"copperControllerAddress";

PPNOptionKey const PPNOptionCopperHostnameSuffix = @"copperHostnameSuffix";

PPNOptionKey const PPNOptionBridgeKeyLength = @"bridgeKeyLength";

PPNOptionKey const PPNOptionRekeyDuration = @"rekeyDuration";

PPNOptionKey const PPNOptionBlindSigningEnabled = @"blindSigningEnabled";

PPNOptionKey const PPNOptionReconnectorInitialTimeToReconnect =
    @"reconnectorInitialTimeToReconnect";

PPNOptionKey const PPNOptionReconnectorSessionConnectionDeadline =
    @"reconnectorSessionConnectionDeadline";

PPNOptionKey const PPNOptionLoggingMode = @"ppnLoggingMode";

PPNOptionKey const PPNCopperHostnameOverride = @"copperHostnameOverride";

PPNOptionKey const PPNUseObjCDatapath = @"useObjCDatapath";

PPNOptionKey const PPNUplinkParallelismEnabled = @"uplinkParallelismEnabled";

PPNOptionKey const PPNOptionCrashAlertEnabled = @"crashAlertEnabled";

PPNOptionKey const PPNOptionCrashpadHandlerDirectoryPath = @"crashpadHandlerDirectoryPath";

PPNOptionKey const PPNOptionCrashpadDatabaseDirectoryPath = @"crashpadDatabaseDirectoryPath";

PPNOptionKey const PPNOptionCrashpadMetricsDirectoryPath = @"crashpadMetricsDirectoryPath";

PPNOptionKey const PPNOptionCrashServerURL = @"crashServerURL";

PPNOptionKey const PPNOptionAppVersion = @"appVersion";

PPNOptionKey const PPNOptionRefreshToken = @"refreshToken";

PPNOptionKey const PPNOptionCountryCode = @"countryCode";

PPNOptionKey const PPNOptionNetworkExtensionCrashReportingEnabled = @"crashReportingEnabled";

PPNOptionKey const PPNOptionNetworkExtensionUploadCrashReportEnabled = @"uploadCrashReportEnabled";

PPNOptionKey const PPNRespectAllNetworkSwitches = @"respectAllNetworkSwitches";

PPNOptionKey const PPNAPIKey = @"apiKey";

PPNOptionKey const PPNOptionIPGeoLevel = @"ipGeoLevel";

#pragma mark - Default Option Values

static PPNOptionKey const PPNOptionDefaultZincURLString =
    @"https://staging.zinc.cloud.cupronickel.goog/auth";

static PPNOptionKey const PPNOptionDefaultZincPublicSigningKeyURLString =
    @"https://staging.zinc.cloud.cupronickel.goog/publickey";

static PPNOptionKey const PPNOptionDefaultZincServiceType = @"g1";

static PPNOptionKey const PPNOptionDefaultBrassURLString =
    @"https://staging.brass.cloud.cupronickel.goog/addegress";

static PPNOptionKey const PPNOptionDefaultInitialDataURLString =
    @"https://staging-phosphor-pa.sandbox.googleapis.com/v1/getInitialData";

static PPNOptionKey const PPNOptionDefaultCopperHostnameSuffix = @"g-tun.com";

#pragma mark - Utility Functions

privacy::krypton::KryptonConfig PPNKryptonConfigFromOptions(
    NSDictionary<PPNOptionKey, id> *options) {
  privacy::krypton::KryptonConfig kryptonConfig;

  NSString *zincURLString = options[PPNOptionZincURLString];
  zincURLString = zincURLString != nullptr ? zincURLString : PPNOptionDefaultZincURLString;
  kryptonConfig.set_zinc_url(std::string(zincURLString.UTF8String));

  NSString *zincPublicSigningKeyURLString = options[PPNOptionZincPublicSigningKeyURLString];
  zincPublicSigningKeyURLString = zincPublicSigningKeyURLString != nullptr
                                      ? zincPublicSigningKeyURLString
                                      : PPNOptionDefaultZincPublicSigningKeyURLString;
  kryptonConfig.set_zinc_public_signing_key_url(
      std::string(zincPublicSigningKeyURLString.UTF8String));

  NSString *zincServiceType = options[PPNOptionZincServiceType];
  zincServiceType = zincServiceType != nullptr ? zincServiceType : PPNOptionDefaultZincServiceType;
  kryptonConfig.set_service_type(std::string(zincServiceType.UTF8String));

  NSString *brassURLString = options[PPNOptionBrassURLString];
  brassURLString = brassURLString != nullptr ? brassURLString : PPNOptionDefaultBrassURLString;
  kryptonConfig.set_brass_url(std::string(brassURLString.UTF8String));

  NSString *initialDataURLString = options[PPNOptionInitialDataURLString];
  initialDataURLString =
      initialDataURLString != nullptr ? initialDataURLString : PPNOptionDefaultInitialDataURLString;
  kryptonConfig.set_initial_data_url(std::string(initialDataURLString.UTF8String));

  NSString *copperControllerAddress = options[PPNOptionCopperControllerAddress];
  if (copperControllerAddress != nullptr) {
    kryptonConfig.set_copper_controller_address(std::string(copperControllerAddress.UTF8String));
  }

  NSArray<NSString *> *copperHostnameSuffix = options[PPNOptionCopperHostnameSuffix];
  if (copperHostnameSuffix.count != 0) {
    for (int i = 0; i < copperHostnameSuffix.count; i++) {
      kryptonConfig.add_copper_hostname_suffix(std::string(copperHostnameSuffix[i].UTF8String));
    }
  } else {
    kryptonConfig.add_copper_hostname_suffix(
        std::string(PPNOptionDefaultCopperHostnameSuffix.UTF8String));
  }

  // Hard-code IPSec as Bridge is not supported.
  kryptonConfig.set_datapath_protocol(privacy::krypton::KryptonConfig::IPSEC);

  NSNumber *bridgeKeyLength = options[PPNOptionBridgeKeyLength];
  if (bridgeKeyLength != nullptr) {
    kryptonConfig.set_cipher_suite_key_length(bridgeKeyLength.intValue);
  }

  NSNumber *rekeyDuration = options[PPNOptionRekeyDuration];
  if (rekeyDuration != nullptr) {
    NSTimeInterval rekeyTimeInterval = rekeyDuration.doubleValue;
    int rekeySeconds = (int)rekeyTimeInterval;
    int rekeyNanos = (rekeyTimeInterval - rekeySeconds) * NSEC_PER_SEC;
    kryptonConfig.mutable_rekey_duration()->set_seconds(rekeySeconds);
    kryptonConfig.mutable_rekey_duration()->set_nanos(rekeyNanos);
  }

  NSNumber *blindSigningEnabled = options[PPNOptionBlindSigningEnabled];
  if (blindSigningEnabled != nullptr) {
    kryptonConfig.set_enable_blind_signing(blindSigningEnabled.boolValue);
  }

  NSNumber *reconnectorInitialTimeToReconnect = options[PPNOptionReconnectorInitialTimeToReconnect];
  if (reconnectorInitialTimeToReconnect != nullptr) {
    int initialTimeToReconnectMS = (int)(reconnectorInitialTimeToReconnect.doubleValue * 1000);
    kryptonConfig.mutable_reconnector_config()->set_initial_time_to_reconnect_msec(
        initialTimeToReconnectMS);
  }

  NSNumber *reconnectionSessionConnectionDeadline =
      options[PPNOptionReconnectorSessionConnectionDeadline];
  if (reconnectionSessionConnectionDeadline != nullptr) {
    int sessionConnectionDeadlineMS =
        (int)(reconnectionSessionConnectionDeadline.doubleValue * 1000);
    kryptonConfig.mutable_reconnector_config()->set_session_connection_deadline_msec(
        sessionConnectionDeadlineMS);
  }

  NSNumber *periodicHealthCheckEnabled = options[PPNPeriodicHealthCheckEnabled];
  if (periodicHealthCheckEnabled != nullptr) {
    kryptonConfig.set_periodic_health_check_enabled(periodicHealthCheckEnabled.boolValue);
  }

  NSNumber *periodicHealthCheckDuration = options[PPNPeriodicHealthCheckDuration];
  if (periodicHealthCheckDuration != nullptr) {
    kryptonConfig.mutable_periodic_health_check_duration()->set_seconds(
        periodicHealthCheckDuration.longLongValue);
  }

  NSString *copperHostnameOverride = options[PPNCopperHostnameOverride];
  if (copperHostnameOverride != nullptr) {
    kryptonConfig.set_copper_hostname_override(std::string(copperHostnameOverride.UTF8String));
  }

  NSNumber *ipv6Enabled = options[PPNIPv6Enabled];
  if (ipv6Enabled != nullptr) {
    kryptonConfig.set_ipv6_enabled(ipv6Enabled.boolValue);
  }

  NSNumber *useObjCDatapath = options[PPNUseObjCDatapath];
  if (useObjCDatapath != nullptr) {
    kryptonConfig.set_use_objc_datapath(useObjCDatapath.boolValue);
  }

  NSNumber *uplinkParallelismEnabled = options[PPNUplinkParallelismEnabled];
  if (uplinkParallelismEnabled != nullptr) {
    kryptonConfig.set_ios_uplink_parallelism_enabled(uplinkParallelismEnabled.boolValue);
  }

  NSNumber *publicMetadataEnabled = options[PPNPublicMetadataEnabled];
  if (publicMetadataEnabled != nullptr) {
    kryptonConfig.set_public_metadata_enabled(publicMetadataEnabled.boolValue);
  }

  NSString *apiKey = options[PPNAPIKey];
  if (apiKey != nullptr) {
    kryptonConfig.set_api_key(std::string(apiKey.UTF8String));
  }

  NSString *level = options[PPNOptionIPGeoLevel];
  if (level != nullptr) {
    privacy::ppn::IpGeoLevel ipGeoLevel;
    if ([level isEqualToString:@"CITY"]) {
      ipGeoLevel = privacy::ppn::IpGeoLevel::CITY;
    } else if ([level isEqualToString:@"COUNTRY"]) {
      ipGeoLevel = privacy::ppn::IpGeoLevel::COUNTRY;
    } else {
      ipGeoLevel = privacy::ppn::IpGeoLevel::IP_GEO_LEVEL_UNSPECIFIED;
    }
    kryptonConfig.set_ip_geo_level(ipGeoLevel);
  }

  return kryptonConfig;
}
