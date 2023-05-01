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

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/** PPN logging mode. */
typedef NS_ENUM(NSUInteger, PPNLoggingMode) {
  /** logs will only be written to the system logs. */
  PPNLoggingModeDefault = 0,
  /** Logs will be written to a file on the device as well as the system logs. */
  PPNLoggingModeDebug = 1,
};

typedef NSString *PPNOptionKey NS_STRING_ENUM;

/**
 * Zinc URL string.
 * If not set, the default value is used.
 */
FOUNDATION_EXTERN PPNOptionKey const PPNOptionZincURLString;
/**
 * Zinc public signing key URL string.
 * If not set, the default value is used.
 */
FOUNDATION_EXTERN PPNOptionKey const PPNOptionZincPublicSigningKeyURLString;
/**
 * Zinc service type.
 * If not set, the default value is used.
 */
FOUNDATION_EXTERN PPNOptionKey const PPNOptionZincServiceType;
/**
 * Brass URL string.
 * If not set, the default value is used.
 */
FOUNDATION_EXTERN PPNOptionKey const PPNOptionBrassURLString;
/**
 * Phosphor InitialData URL string.
 * If not set, the default value is used.
 */
FOUNDATION_EXTERN PPNOptionKey const PPNOptionInitialDataURLString;
/**
 * Whether the IPSec is enabled.
 * Set @YES to enable the IPSec or set @NO to disable the IPSec.
 */
FOUNDATION_EXTERN PPNOptionKey const PPNOptionIPSecEnabled;
/**
 * Zinc OAuth scope.
 * If not set, the default value is used.
 */
FOUNDATION_EXTERN PPNOptionKey const PPNOptionZincOAuthScope;
/**
 * Copper controller address.
 * If not set, the default value is used.
 */
FOUNDATION_EXTERN PPNOptionKey const PPNOptionCopperControllerAddress;
/**
 * Copper hostname suffix list.
 * If empty, add the default value to it.
 */
FOUNDATION_EXTERN PPNOptionKey const PPNOptionCopperHostnameSuffix;
/**
 * Whether bridge is enabled.
 * Set @YES to enable the bridge or set @NO to disable the bridge. If not set, the default value is
 * used.
 */
FOUNDATION_EXTERN PPNOptionKey const PPNOptionBridgeOnPPNEnabled;
/**
 * Bridge key length.
 * If not set, the default value is used.
 */
FOUNDATION_EXTERN PPNOptionKey const PPNOptionBridgeKeyLength;
/**
 * Rekey duration in seconds.
 * If not set, the default value is used.
 */
FOUNDATION_EXTERN PPNOptionKey const PPNOptionRekeyDuration;
/**
 * Whether blind signing is enabled.
 * Set @YES to enable the blind signing or set @NO to disable the blind signing. If not set, the
 * default value is used.
 */
FOUNDATION_EXTERN PPNOptionKey const PPNOptionBlindSigningEnabled;
/**
 * Whether Krypton crash signal handler should be installed.
 * Set @YES to install the Krypton crash signal handler or set @NO to skip the handler. If not set,
 * the default value is used.
 */
FOUNDATION_EXTERN PPNOptionKey const PPNOptionShouldInstallKryptonCrashSignalHandler;

/**
 * Reconnector initial reconnect time in seconds.
 * If not set, the default value is used.
 */
FOUNDATION_EXTERN PPNOptionKey const PPNOptionReconnectorInitialTimeToReconnect;
/**
 * Reconnector session connection deadline in seconds.
 * If not set, the default value is used.
 */
FOUNDATION_EXTERN PPNOptionKey const PPNOptionReconnectorSessionConnectionDeadline;
/**
 * The logging mode.
 * If not set, the default value will be used.
 */
FOUNDATION_EXTERN PPNOptionKey const PPNOptionLoggingMode;
/**
 * Whether or not periodic health check is enabled.
 */
FOUNDATION_EXTERN PPNOptionKey const PPNPeriodicHealthCheckEnabled;
/**
 * How often a periodic health check should be conducted.
 * The number of duration is in seconds.
 */
FOUNDATION_EXTERN PPNOptionKey const PPNPeriodicHealthCheckDuration;
/**
 * For tests and probers, this overrides the copper_controller_address and the
 * copper hostname from the zinc backend and sets the control_plane_sock_addr
 * sent to brass.
 */
FOUNDATION_EXTERN PPNOptionKey const PPNCopperHostnameOverride;

/** Whether or not PPN can connect to IPv6 Copper addresses. */
FOUNDATION_EXTERN PPNOptionKey const PPNIPv6Enabled;

/** Whether or not crash alert should be shown to the user. */
FOUNDATION_EXTERN PPNOptionKey const PPNOptionCrashAlertEnabled;

/** Whether or not debug logs should be included in the crash report. */
FOUNDATION_EXTERN PPNOptionKey const PPNOptionCrashDebugLoggingEnabled;

/**
 * The Crashpad handler directory path.
 */
FOUNDATION_EXTERN PPNOptionKey const PPNOptionCrashpadHandlerDirectoryPath;
/**
 * The Crashpad database directory path.
 */
FOUNDATION_EXTERN PPNOptionKey const PPNOptionCrashpadDatabaseDirectoryPath;
/**
 * The Crashpad metrics directory path.
 */
FOUNDATION_EXTERN PPNOptionKey const PPNOptionCrashpadMetricsDirectoryPath;

/**
 * The crash server URL.
 */
FOUNDATION_EXTERN PPNOptionKey const PPNOptionCrashServerURL;

/**
 * The app version.
 */
FOUNDATION_EXTERN PPNOptionKey const PPNOptionAppVersion;

/**
 * The OAuth 2.0 refresh token
 */
FOUNDATION_EXTERN PPNOptionKey const PPNOptionRefreshToken;

/**
 * Country code of the user who uses PPN.
 */
FOUNDATION_EXTERN PPNOptionKey const PPNOptionCountryCode;

/**
 * Indicates whether the network extension crash reporting is enabled;
 */
FOUNDATION_EXTERN PPNOptionKey const PPNOptionNetworkExtensionCrashReportingEnabled;

/**
 * Indicates whether uploading network extension crash report is enabled.
 */
FOUNDATION_EXTERN PPNOptionKey const PPNOptionNetworkExtensionUploadCrashReportEnabled;

/**
 * Indicates whether to use Public Metadata RPCs.
 */
FOUNDATION_EXTERN PPNOptionKey const PPNPublicMetadataEnabled;

/**
 * Stores the api key for making calls to beryllium API.
 */
FOUNDATION_EXTERN PPNOptionKey const PPNAPIKey;

/**
 * Indicates whether to always reconnect when xenon detects a network switch.
 */
FOUNDATION_EXTERN PPNOptionKey const PPNRespectAllNetworkSwitches;

/**
 * Sets the level of granularity for IP-geo mapping.
 */
FOUNDATION_EXTERN PPNOptionKey const PPNOptionIPGeoLevel;

/**
 * Indicates whether debug mode is allowed.
 */
FOUNDATION_EXTERN PPNOptionKey const PPNDebugModeAllowed;

NS_ASSUME_NONNULL_END
