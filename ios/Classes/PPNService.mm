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

#import "googlemac/iPhone/Shared/PPN/API/PPNService.h"

#import <mach/mach.h>

#import "googlemac/iPhone/Shared/PPN/API/PPNDisconnectionStatus.h"

#import "googlemac/iPhone/Shared/PPN/API/PPNLog.h"
#import "googlemac/iPhone/Shared/PPN/API/PPNOptions.h"
#import "googlemac/iPhone/Shared/PPN/API/PPNServiceDelegate.h"
#import "googlemac/iPhone/Shared/PPN/Classes/PPNOptions+Internal.h"
#import "googlemac/iPhone/Shared/PPN/Classes/PPNProtoUtils.h"
#import "googlemac/iPhone/Shared/PPN/Classes/PPNTelemetryManager.h"
#import "googlemac/iPhone/Shared/PPN/Krypton/API/PPNKryptonService.h"
#import "googlemac/iPhone/Shared/PPN/Krypton/API/PPNKryptonServiceDelegate.h"
#import "googlemac/iPhone/Shared/PPN/Xenon/API/PPNNWPathMonitor.h"
#import "googlemac/iPhone/Shared/PPN/Xenon/API/PPNNWPathMonitorDelegate.h"

#include <stdatomic.h>
#include "privacy/net/krypton/proto/krypton_config.proto.h"

static const NSTimeInterval kCollectDebugInfoPeriod = 300;
static const NSTimeInterval kLogDebugInfoTimeout = 30;

NSNumber *PPNMemoryUsageInBytes() {
  task_vm_info_data_t taskInfoData;
  mach_msg_type_number_t size = TASK_VM_INFO_COUNT;
  kern_return_t err = task_info(mach_task_self(), TASK_VM_INFO, (task_info_t)&taskInfoData, &size);
  if (err == KERN_SUCCESS) {
    return @(taskInfoData.phys_footprint);
  }

  return @0;
}

@interface PPNService () <PPNKryptonServiceDelegate, PPNNWPathMonitorDelegate>
@end

@implementation PPNService {
  /**
   * The Krypton config used to start the Krypton service.
   */
  privacy::krypton::KryptonConfig _kryptonConfig;

  /**
   * The Krypton service that starts / stops the VPN data tunnel.
   */
  PPNKryptonService *_kryptonService;

  /**
   * The NWPath monitor.
   */
  PPNNWPathMonitor *_nwPathMonitor;

  /**
   * Atomic bool indicating whether the PPN service is running or not.
   */
  std::atomic<bool> _running;

  /**
   * Dispatch queue for calling into Krypton.
   */
  dispatch_queue_t _kryptonDispatchQueue;

  /**
   * Dispatch queue for calling delegate methods.
   */
  dispatch_queue_t _delegateDispatchQueue;

  dispatch_source_t _kryptonDebugInfoLoggingTimer;

  PPNTelemetryManager *_telemetryManager;
}

- (instancetype)initWithOptions:(NSDictionary<PPNOptionKey, id> *)options
                      OAuthManager:(id<PPNOAuthManaging>)OAuthManager
    virtualNetworkInterfaceManager:
        (id<PPNVirtualNetworkInterfaceManaging>)virtualNetworkInterfaceManager
                 UDPSessionManager:(id<PPNUDPSessionManaging>)UDPSessionManager {
  self = [super init];
  if (self != nullptr) {
    _kryptonDispatchQueue = dispatch_queue_create("com.google.ppn.krypton", DISPATCH_QUEUE_SERIAL);
    _delegateDispatchQueue = dispatch_get_main_queue();

    _kryptonConfig = PPNKryptonConfigFromOptions(options);
    _kryptonService = [[PPNKryptonService alloc] initWithOAuthManager:OAuthManager
                                       virtualNetworkInterfaceManager:virtualNetworkInterfaceManager
                                                 ppnUDPSessionManager:UDPSessionManager
                                                           timerQueue:_kryptonDispatchQueue];
    _kryptonService.delegate = self;

    _nwPathMonitor = [[PPNNWPathMonitor alloc] initWithOptions:options];
    _nwPathMonitor.delegate = self;

    _running = false;

    _kryptonDebugInfoLoggingTimer = nullptr;
    _telemetryManager = [[PPNTelemetryManager alloc] initWithClock:[[PPNClock alloc] init]];
  }
  return self;
}

- (void)dealloc {
  @synchronized(self) {
    if (_kryptonDebugInfoLoggingTimer != nullptr) {
      dispatch_source_cancel(_kryptonDebugInfoLoggingTimer);
    }
  }
}

- (void)start {
  _running = true;
  dispatch_async(_kryptonDispatchQueue, ^{
    [_telemetryManager notifyStarted];
    [_kryptonService startWithConfiguration:_kryptonConfig];
    PPNLog(@"[%@] Krypton started.", self.debugDescription);
    [_nwPathMonitor startMonitor];

    dispatch_async(_delegateDispatchQueue, ^{
      if ([self.delegate respondsToSelector:@selector(PPNServiceDidStart:)]) {
        [self.delegate PPNServiceDidStart:self];
      }
    });

    [self logKryptonDebugInfo];
    [self schedulePeriodicKryptonDebugInfoLoggingIfNecessary];
  });
}

- (void)stop {
  [self stopWithError:nil];
}

- (BOOL)isRunning {
  return _running.load();
}

- (NSDictionary<NSString *, id> *)debugInfo {
  return @{};
}

- (void)stopWithError:(nullable NSError *)error {
  _running = false;

  dispatch_async(_kryptonDispatchQueue, ^{
    [self logKryptonDebugInfo];
    PPNLog(@"[%@] Stopping Krypton...", self.debugDescription);
    [_kryptonService stop];
    PPNLog(@"[%@] Krypton stopped. Error: %@.", self.debugDescription, error);
    [_nwPathMonitor stopMonitor];
    [_telemetryManager notifyStopped];

    dispatch_async(_delegateDispatchQueue, ^{
      PPNLog(@"[%@] Notifying delegate that PPN stopped with error: %@", self.debugDescription,
             error);
      if ([self.delegate respondsToSelector:@selector(PPNService:didStopWithError:)]) {
        [self.delegate PPNService:self didStopWithError:error];
      }
    });
  });
}

- (PPNTelemetry *)collectTelemetry {
  PPNLog(@"Collecting telemetry from Krypton.");
  privacy::krypton::KryptonTelemetry kryptonTelemetry = [_kryptonService collectTelemetry];
  PPNTelemetry *ppnTelemetry = [_telemetryManager collect:kryptonTelemetry];
  return ppnTelemetry;
}

#pragma mark - Krypton Debugging Logging

/** This method should only be called on the @c _dispatchQueue. */
- (void)schedulePeriodicKryptonDebugInfoLoggingIfNecessary {
  @synchronized(self) {
    if (_kryptonDebugInfoLoggingTimer != nullptr) {
      PPNLog(@"[%@] Not starting Krypton debug timer, because it's already set.",
             self.debugDescription);
      return;
    }

    PPNLog(@"[%@] Starting Krypton debug timer for every %lf seconds.", self.debugDescription,
           kCollectDebugInfoPeriod);
    __weak PPNService *weakSelf = self;

    _kryptonDebugInfoLoggingTimer =
        dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, _kryptonDispatchQueue);
    if (_kryptonDebugInfoLoggingTimer == nullptr) {
      PPNLog(@"[%@] Unable to create Krypton debug info timer.", self.debugDescription);
      return;
    }

    int64_t interval = static_cast<int64_t>(kCollectDebugInfoPeriod * NSEC_PER_SEC);
    int64_t leeway = 10 * NSEC_PER_SEC;
    dispatch_source_set_timer(_kryptonDebugInfoLoggingTimer, dispatch_walltime(nullptr, interval),
                              interval, leeway);
    dispatch_source_set_event_handler(_kryptonDebugInfoLoggingTimer, ^{
      PPNLog(@"[%p] Krypton debug timer expired.", weakSelf);
      [weakSelf logKryptonDebugInfo];
    });
    dispatch_resume(_kryptonDebugInfoLoggingTimer);
  }
}

- (void)stopPeriodicKryptonDebugInfoLogging {
  PPNLog(@"Invalidating Krypton debug timer.");
  @synchronized(self) {
    dispatch_source_cancel(_kryptonDebugInfoLoggingTimer);
    _kryptonDebugInfoLoggingTimer = nil;
  }
  dispatch_async(_kryptonDispatchQueue, ^{
    [self logKryptonDebugInfo];
  });
}

- (void)logKryptonDebugInfo {
  // A boolean to track whether the logging actually completed.
  NSLock *lock = [[NSLock alloc] init];
  __block BOOL logged = NO;

  dispatch_async(_kryptonDispatchQueue, ^{
    PPNLog(@"[%@] Fetching Krypton debug info...", self.debugDescription);

    privacy::krypton::KryptonDebugInfo debugInfo = [self->_kryptonService debugInfo];

    NSNumber *memoryUsageInBytes = PPNMemoryUsageInBytes();
    NSMutableDictionary<NSString *, id> *debugInfoDictionary =
        [PPNKryptonDebugInfoToNSDictionary(debugInfo) mutableCopy];
    debugInfoDictionary[@"memory_usage_in_bytes"] =
        memoryUsageInBytes.integerValue > 0 ? memoryUsageInBytes : @"Unknown";

    PPNLog(@"[%@] Krypton debug info: %@.", self.debugDescription, debugInfoDictionary);

    [lock lock];
    logged = YES;
    [lock unlock];
  });

  dispatch_time_t timeout = dispatch_time(DISPATCH_TIME_NOW, kLogDebugInfoTimeout * NSEC_PER_SEC);
  dispatch_after(timeout, dispatch_get_main_queue(), ^{
    BOOL logCompleted = NO;
    [lock lock];
    logCompleted = logged;
    [lock unlock];

    if (!logCompleted) {
      PPNLog(@"Fetching debug info timed out.");
    }
  });
}

#pragma mark - PPNKryptonServiceDelegate

- (void)kryptonService:(PPNKryptonService *)kryptonService
            didConnect:(PPNConnectionStatus *)status {
  PPNLog(@"[%@] Krypton connected. Status: %@.", self.debugDescription, status);
  [_telemetryManager notifyConnected];
  dispatch_async(_delegateDispatchQueue, ^{
    if ([self.delegate respondsToSelector:@selector(PPNService:didConnectWithStatus:)]) {
      [self.delegate PPNService:self didConnectWithStatus:status];
    }
  });
}

- (void)kryptonServiceConnecting:(PPNKryptonService *)kryptonService {
  PPNLog(@"[%@] Krypton connecting: trying to start a new session", self.debugDescription);
  dispatch_async(_delegateDispatchQueue, ^{
    if ([self.delegate respondsToSelector:@selector(PPNServiceConnecting:)]) {
      [self.delegate PPNServiceConnecting:self];
    }
  });
}

- (void)kryptonServiceDidConnectControlPlane:(PPNKryptonService *)kryptonService {
  PPNLog(@"[%@] Krypton control plane connected.", self.debugDescription);
}

- (void)kryptonService:(PPNKryptonService *)kryptonService
       didUpdateStatus:(PPNConnectionStatus *)status {
  PPNLog(@"[%@] Krypton status updated. Status: %@.", self.debugDescription, status);
  dispatch_async(_delegateDispatchQueue, ^{
    if ([self.delegate respondsToSelector:@selector(PPNService:didUpdateStatus:)]) {
      [self.delegate PPNService:self didUpdateStatus:status];
    }
  });
}

- (void)kryptonService:(PPNKryptonService *)kryptonService
         didDisconnect:(PPNDisconnectionStatus *)disconnectionStatus {
  PPNLog(@"[%@] Krypton disconnected with status: %@", self.debugDescription,
         disconnectionStatus.description);
  [_telemetryManager notifyDisconnected];
  dispatch_async(_delegateDispatchQueue, ^{
    if ([self.delegate respondsToSelector:@selector(PPNService:didDisconnect:)]) {
      [self.delegate PPNService:self didDisconnect:disconnectionStatus];
    }
  });
}

- (void)kryptonService:(PPNKryptonService *)kryptonService
      didFailWithError:(NSError *)error
           networkInfo:(PPNNetworkInfo *)networkInfo {
  PPNLog(@"[%@] Krypton network failed. Error: %@. NetworkInfo: %@.", self.debugDescription, error,
         networkInfo);
}

- (void)kryptonService:(PPNKryptonService *)kryptonService
    didPermanentlyFailWithError:(NSError *)error {
  PPNLog(@"[%@] Krypton permanently failed. Error: %@.", self.debugDescription, error);
  [self stopWithError:error];
  [self stopPeriodicKryptonDebugInfoLogging];
}

- (void)kryptonServiceDidCrash:(PPNKryptonService *)kryptonService {
  PPNLog(@"[%@] Krypton has crashed.", self.debugDescription);
}

- (void)kryptonService:(PPNKryptonService *)kryptonService
    waitingToReconnect:(PPNReconnectStatus *)status {
  PPNLog(@"[%@] Krypton waiting to reconnect: %@.", self.debugDescription, status);
  dispatch_async(_delegateDispatchQueue, ^{
    if ([self.delegate respondsToSelector:@selector(PPNService:waitingToReconnect:)]) {
      [self.delegate PPNService:self waitingToReconnect:status];
    }
  });
}

#pragma mark - PPNNWPathMonitorDelegate

- (void)NWPathMonitor:(PPNNWPathMonitor *)pathMonitor
     didDetectNetwork:(::privacy::krypton::NetworkInfo)networkInfo {
  PPNLog(@"[%@] Path monitor did detect network.", self.debugDescription);
  [_telemetryManager notifyNetworkAvailable];
  dispatch_async(_kryptonDispatchQueue, ^{
    [_kryptonService setNetwork:networkInfo];
  });
}

- (void)NWPathMonitorDidDetectNoNetwork:(PPNNWPathMonitor *)pathMonitor {
  PPNLog(@"[%@] Path monitor did detect no network.", self.debugDescription);
  [_telemetryManager notifyNetworkUnavailable];
  dispatch_async(_kryptonDispatchQueue, ^{
    [_kryptonService setNoNetworkAvailable];
  });
}

@end
