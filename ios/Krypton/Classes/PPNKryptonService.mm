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

#import "googlemac/iPhone/Shared/PPN/Krypton/API/PPNKryptonService.h"

#import "googlemac/iPhone/Shared/PPN/API/PPNVirtualNetworkInterfaceManaging.h"
#import "googlemac/iPhone/Shared/PPN/Krypton/API/PPNHttpFetcher.h"
#import "googlemac/iPhone/Shared/PPN/Krypton/API/PPNKryptonServiceDelegate.h"
#import "googlemac/iPhone/Shared/PPN/Krypton/Classes/PPNKryptonNotification.h"
#import "googlemac/iPhone/Shared/PPN/Krypton/Classes/PPNKryptonNotificationDelegate.h"
#import "googlemac/iPhone/Shared/PPN/Krypton/Classes/PPNOAuth.h"
#import "googlemac/iPhone/Shared/PPN/Krypton/Classes/PPNTimer.h"
#import "googlemac/iPhone/Shared/PPN/Krypton/Classes/PPNVPNService.h"

#import "privacy/net/common/proto/ppn_options.proto.h"
#import "privacy/net/krypton/krypton.h"
#import "privacy/net/krypton/timer_manager.h"

@interface PPNKryptonService () <PPNKryptonNotificationDelegate>
@end

@implementation PPNKryptonService {
  privacy::krypton::PPNHttpFetcher _http_fetcher;
  std::unique_ptr<privacy::krypton::PPNTimer> _ppn_timer;
  std::unique_ptr<privacy::krypton::PPNKryptonNotification> _notification;
  std::unique_ptr<privacy::krypton::PPNOAuth> _oauth;
  std::unique_ptr<privacy::krypton::TimerManager> _timer_manager;
  std::unique_ptr<privacy::krypton::Krypton> _krypton;
  std::unique_ptr<privacy::krypton::PPNVPNService> _vpn_service;
}

- (instancetype)initWithOAuthManager:(id<PPNOAuthManaging>)OAuthManager
      virtualNetworkInterfaceManager:
          (id<PPNVirtualNetworkInterfaceManaging>)virtualNetworkInterfaceManager
                ppnUDPSessionManager:(id<PPNUDPSessionManaging>)ppnUDPSessionManager
                          timerQueue:(dispatch_queue_t)timerQueue {
  self = [super init];
  if (self != nullptr) {
    _vpn_service = std::make_unique<privacy::krypton::PPNVPNService>(
        ppnUDPSessionManager, virtualNetworkInterfaceManager);
    _oauth = std::make_unique<privacy::krypton::PPNOAuth>(OAuthManager);
    _ppn_timer = std::make_unique<privacy::krypton::PPNTimer>(timerQueue);
    _timer_manager = std::make_unique<privacy::krypton::TimerManager>(_ppn_timer.get());
    _notification = std::make_unique<privacy::krypton::PPNKryptonNotification>(self);
  }
  return self;
}

- (void)startWithConfiguration:(const privacy::krypton::KryptonConfig &)configuration {
  _krypton = std::make_unique<privacy::krypton::Krypton>(
      &_http_fetcher, _notification.get(), _vpn_service.get(), _oauth.get(), _timer_manager.get());
  _krypton->Start(configuration);
}

- (void)stop {
  _krypton->Stop();
}

- (absl::Status)setNetwork:(const privacy::krypton::NetworkInfo &)networkInfo {
  return _krypton->SetNetwork(networkInfo);
}

- (absl::Status)setNoNetworkAvailable {
  return _krypton->SetNoNetworkAvailable();
}

- (void)setSafeDisconnectEnabled:(BOOL)enabled {
  _krypton->SetSafeDisconnectEnabled(enabled);
}

- (BOOL)isSafeDisconnectEnabled {
  return _krypton->IsSafeDisconnectEnabled();
}

- (privacy::krypton::KryptonDebugInfo)debugInfo {
  privacy::krypton::KryptonDebugInfo debugInfo;
  _krypton->GetDebugInfo(&debugInfo);
  return debugInfo;
}

- (privacy::krypton::KryptonTelemetry)collectTelemetry {
  privacy::krypton::KryptonTelemetry kryptonTelemetry;
  _krypton->CollectTelemetry(&kryptonTelemetry);
  return kryptonTelemetry;
}

- (void)setIPGeoLevel:(privacy::ppn::IpGeoLevel)level {
  _krypton->SetIpGeoLevel(static_cast<privacy::ppn::IpGeoLevel>(level));
}

#pragma mark - PPNKryptonNotificationDelegate

- (void)kryptonNotification:(privacy::krypton::PPNKryptonNotification &)kryptonNotification
                 didConnect:(PPNConnectionStatus *)status {
  if ([_delegate respondsToSelector:@selector(kryptonService:didConnect:)]) {
    [_delegate kryptonService:self didConnect:status];
  }
}

- (void)kryptonNotificationConnecting:
    (privacy::krypton::PPNKryptonNotification &)kryptonNotification {
  if ([_delegate respondsToSelector:@selector(kryptonServiceConnecting:)]) {
    [_delegate kryptonServiceConnecting:self];
  }
}

- (void)kryptonNotificationDidConnectControlPlane:
    (privacy::krypton::PPNKryptonNotification &)kryptonNotification {
  if ([_delegate respondsToSelector:@selector(kryptonServiceDidConnectControlPlane:)]) {
    [_delegate kryptonServiceDidConnectControlPlane:self];
  }
}

- (void)kryptonNotification:(privacy::krypton::PPNKryptonNotification &)kryptonNotification
            didUpdateStatus:(PPNConnectionStatus *)status {
  if ([_delegate respondsToSelector:@selector(kryptonService:didUpdateStatus:)]) {
    [_delegate kryptonService:self didUpdateStatus:status];
  }
}

- (void)kryptonNotification:(privacy::krypton::PPNKryptonNotification &)kryptonNotification
              didDisconnect:(PPNDisconnectionStatus *)disconnectionStatus {
  if ([_delegate respondsToSelector:@selector(kryptonService:didDisconnect:)]) {
    [_delegate kryptonService:self didDisconnect:disconnectionStatus];
  }
}

- (void)kryptonNotification:(privacy::krypton::PPNKryptonNotification &)kryptonNotification
           didFailWithError:(NSError *)error
                networkInfo:(PPNNetworkInfo *)networkInfo {
  if ([_delegate respondsToSelector:@selector(kryptonService:didFailWithError:networkInfo:)]) {
    [_delegate kryptonService:self didFailWithError:error networkInfo:networkInfo];
  }
}

- (void)kryptonNotification:(privacy::krypton::PPNKryptonNotification &)kryptonNotification
    didPermanentlyFailWithError:(NSError *)error {
  if ([_delegate respondsToSelector:@selector(kryptonService:didPermanentlyFailWithError:)]) {
    [_delegate kryptonService:self didPermanentlyFailWithError:error];
  }
}

- (void)kryptonNotificationDidCrash:
    (privacy::krypton::PPNKryptonNotification &)kryptonNotification {
  if ([_delegate respondsToSelector:@selector(kryptonServiceDidCrash:)]) {
    [_delegate kryptonServiceDidCrash:self];
  }
}

- (void)kryptonNotification:(privacy::krypton::PPNKryptonNotification &)kryptonNotification
         waitingToReconnect:(PPNReconnectStatus *)status {
  if ([_delegate respondsToSelector:@selector(kryptonService:waitingToReconnect:)]) {
    [_delegate kryptonService:self waitingToReconnect:status];
  }
}

#pragma mark - Test

- (privacy::krypton::PPNKryptonNotification &)kryptonNotification {
  return *_notification;
}

@end
