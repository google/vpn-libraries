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

#import "googlemac/iPhone/Shared/PPN/API/PPNOptions.h"

#import "google/protobuf/duration.proto.h"
#import "googlemac/iPhone/Shared/PPN/Classes/PPNOptions+Internal.h"

#include "privacy/net/common/proto/ppn_options.proto.h"
#include "privacy/net/krypton/proto/krypton_config.proto.h"

#import <XCTest/XCTest.h>

@interface PPNOptionsTest : XCTestCase
@end

@implementation PPNOptionsTest

- (void)testKryptonConfigFromOptionsWithEmptyOptions {
  privacy::krypton::KryptonConfig kryptonConfig = PPNKryptonConfigFromOptions(@{});

  // Verify the proto fields that have defaults in the PPNOptions.
  NSString *zincURLString = [[NSString alloc] initWithUTF8String:kryptonConfig.zinc_url().c_str()];
  XCTAssertEqualObjects(zincURLString, @"https://staging.zinc.cloud.cupronickel.goog/auth");
  NSString *zincPublicSigningKeyURLString =
      [[NSString alloc] initWithUTF8String:kryptonConfig.zinc_public_signing_key_url().c_str()];
  XCTAssertEqualObjects(zincPublicSigningKeyURLString,
                        @"https://staging.zinc.cloud.cupronickel.goog/publickey");
  NSString *zincServiceType =
      [[NSString alloc] initWithUTF8String:kryptonConfig.service_type().c_str()];
  XCTAssertEqualObjects(zincServiceType, @"g1");
  NSString *brassURLString =
      [[NSString alloc] initWithUTF8String:kryptonConfig.brass_url().c_str()];
  XCTAssertEqualObjects(brassURLString, @"https://staging.brass.cloud.cupronickel.goog/addegress");
  NSString *initialDataURLString =
      [[NSString alloc] initWithUTF8String:kryptonConfig.initial_data_url().c_str()];
  XCTAssertEqualObjects(initialDataURLString,
                        @"https://staging-phosphor-pa.sandbox.googleapis.com/v1/getInitialData");
  NSString *copperHostnameOverride =
      [[NSString alloc] initWithUTF8String:kryptonConfig.copper_hostname_override().c_str()];
  XCTAssertEqualObjects(copperHostnameOverride, @"");

  // Verify the proto fields that don't have defaults in the PPNOptions.
  XCTAssertFalse(kryptonConfig.has_copper_controller_address());
  XCTAssertEqual(kryptonConfig.datapath_protocol(), privacy::krypton::KryptonConfig::IPSEC);
  XCTAssertFalse(kryptonConfig.has_cipher_suite_key_length());
  XCTAssertFalse(kryptonConfig.has_rekey_duration());
  XCTAssertFalse(kryptonConfig.has_enable_blind_signing());
  XCTAssertFalse(kryptonConfig.has_reconnector_config());
  XCTAssertEqual(kryptonConfig.copper_hostname_suffix_size(), 1);
  NSString *copperHostnameSuffixElem =
      [[NSString alloc] initWithUTF8String:kryptonConfig.copper_hostname_suffix(0).c_str()];
  XCTAssertEqualObjects(copperHostnameSuffixElem, @"g-tun.com");
  XCTAssertTrue(kryptonConfig.ipv6_enabled());
  XCTAssertFalse(kryptonConfig.public_metadata_enabled());
  XCTAssertFalse(kryptonConfig.debug_mode_allowed());
  XCTAssertFalse(kryptonConfig.has_api_key());
  NSString *apiKey = [[NSString alloc] initWithUTF8String:kryptonConfig.api_key().c_str()];
  XCTAssertEqualObjects(apiKey, @"");
  XCTAssertFalse(kryptonConfig.has_ip_geo_level());
}

- (void)testKryptonConfigFromOptions {
  NSDictionary<PPNOptionKey, id> *options = @{
    PPNOptionZincURLString : @"zinc_url",
    PPNOptionZincPublicSigningKeyURLString : @"zinc_public_signing_key_url",
    PPNOptionZincServiceType : @"service_type",
    PPNOptionBrassURLString : @"brass_url",
    PPNOptionInitialDataURLString : @"initial_data_url",
    PPNOptionCopperControllerAddress : @"copper_controller_address",
    PPNOptionCopperHostnameSuffix : @[ @"copperHostnameSuffix" ],
    PPNOptionBridgeKeyLength : @1024,
    PPNOptionRekeyDuration : @30.5,
    PPNOptionBlindSigningEnabled : @NO,
    PPNOptionReconnectorInitialTimeToReconnect : @2,
    PPNOptionReconnectorSessionConnectionDeadline : @60,
    PPNCopperHostnameOverride : @"copper_hostname_override",
    PPNIPv6Enabled : @NO,
    PPNPublicMetadataEnabled : @YES,
    PPNAPIKey : @"beryllium_api_key",
    PPNOptionIPGeoLevel : @"CITY",
    PPNDebugModeAllowed : @YES,
  };
  privacy::krypton::KryptonConfig kryptonConfig = PPNKryptonConfigFromOptions(options);

  NSString *zincURLString = [[NSString alloc] initWithUTF8String:kryptonConfig.zinc_url().c_str()];
  XCTAssertEqualObjects(zincURLString, @"zinc_url");
  NSString *zincPublicSigningKeyURLString =
      [[NSString alloc] initWithUTF8String:kryptonConfig.zinc_public_signing_key_url().c_str()];
  XCTAssertEqualObjects(zincPublicSigningKeyURLString, @"zinc_public_signing_key_url");
  NSString *zincServiceType =
      [[NSString alloc] initWithUTF8String:kryptonConfig.service_type().c_str()];
  XCTAssertEqualObjects(zincServiceType, @"service_type");
  NSString *brassURLString =
      [[NSString alloc] initWithUTF8String:kryptonConfig.brass_url().c_str()];
  XCTAssertEqualObjects(brassURLString, @"brass_url");
  NSString *initialDataURLString =
      [[NSString alloc] initWithUTF8String:kryptonConfig.initial_data_url().c_str()];
  XCTAssertEqualObjects(initialDataURLString, @"initial_data_url");
  NSString *copperControllerAddress =
      [[NSString alloc] initWithUTF8String:kryptonConfig.copper_controller_address().c_str()];
  XCTAssertEqualObjects(copperControllerAddress, @"copper_controller_address");
  NSString *copperHostnameOverride =
      [[NSString alloc] initWithUTF8String:kryptonConfig.copper_hostname_override().c_str()];
  XCTAssertEqualObjects(copperHostnameOverride, @"copper_hostname_override");
  NSString *apiKey = [[NSString alloc] initWithUTF8String:kryptonConfig.api_key().c_str()];
  XCTAssertEqualObjects(apiKey, @"beryllium_api_key");
  XCTAssertEqual(kryptonConfig.ip_geo_level(), privacy::ppn::CITY);

  XCTAssertEqual(kryptonConfig.datapath_protocol(), privacy::krypton::KryptonConfig::IPSEC);
  XCTAssertEqual(kryptonConfig.cipher_suite_key_length(), 1024u);
  XCTAssertEqual(kryptonConfig.rekey_duration().seconds(), 30);
  XCTAssertEqual(kryptonConfig.rekey_duration().nanos(), 0.5 * NSEC_PER_SEC);
  XCTAssertFalse(kryptonConfig.enable_blind_signing());
  XCTAssertEqual(kryptonConfig.reconnector_config().initial_time_to_reconnect_msec(), 2000u);
  XCTAssertEqual(kryptonConfig.reconnector_config().session_connection_deadline_msec(), 60000u);
  XCTAssertEqual(kryptonConfig.copper_hostname_suffix(0), "copperHostnameSuffix");
  XCTAssertFalse(kryptonConfig.ipv6_enabled());
  XCTAssertTrue(kryptonConfig.public_metadata_enabled());
  XCTAssertTrue(kryptonConfig.debug_mode_allowed());
}

@end
