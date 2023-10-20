// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "privacy/net/krypton/session_manager.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>

#include "privacy/net/krypton/add_egress_response.h"
#include "privacy/net/krypton/datapath_interface.h"
#include "privacy/net/krypton/endpoint.h"
#include "privacy/net/krypton/json_keys.h"
#include "privacy/net/krypton/pal/mock_http_fetcher_interface.h"
#include "privacy/net/krypton/pal/mock_oauth_interface.h"
#include "privacy/net/krypton/pal/mock_timer_interface.h"
#include "privacy/net/krypton/pal/mock_vpn_service_interface.h"
#include "privacy/net/krypton/proto/debug_info.proto.h"
#include "privacy/net/krypton/proto/http_fetcher.proto.h"
#include "privacy/net/krypton/proto/network_info.proto.h"
#include "privacy/net/krypton/proto/tun_fd_data.proto.h"
#include "privacy/net/krypton/session.h"
#include "privacy/net/krypton/timer_manager.h"
#include "privacy/net/krypton/tunnel_manager_interface.h"
#include "privacy/net/krypton/utils/json_util.h"
#include "privacy/net/krypton/utils/looper.h"
#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/strings/str_cat.h"
#include "third_party/absl/synchronization/notification.h"
#include "third_party/absl/time/time.h"
#include "third_party/json/include/nlohmann/json.hpp"
#include "third_party/json/include/nlohmann/json_fwd.hpp"

namespace privacy {
namespace krypton {
namespace {

MATCHER_P(UrlMatcher, url, "Matches URL field of HttpRequest") {
  return arg.url() == url;
}

using ::testing::_;
using ::testing::EqualsProto;
using ::testing::Return;

class MockTunnelManager : public TunnelManagerInterface {
 public:
  MOCK_METHOD(absl::Status, Start, (), (override));
  MOCK_METHOD(void, Stop, (), (override));
  MOCK_METHOD(void, SetSafeDisconnectEnabled, (bool), (override));
  MOCK_METHOD(bool, IsSafeDisconnectEnabled, (), (override));
  MOCK_METHOD(void, DatapathStarted, (), (override));
  MOCK_METHOD(absl::Status, CreateTunnel, (TunFdData, bool), (override));
  MOCK_METHOD(absl::Status, ResumeTunnel, (), (override));
  MOCK_METHOD(absl::Status, RecreateTunnel, (), (override));
  MOCK_METHOD(void, DatapathStopped, (bool), (override));
  MOCK_METHOD(bool, IsTunnelActive, (), (override));
};

class MockDatapath : public DatapathInterface {
 public:
  MOCK_METHOD(absl::Status, Start,
              (const AddEgressResponse&, const TransformParams& params),
              (override));
  MOCK_METHOD(void, Stop, (), (override));
  MOCK_METHOD(void, RegisterNotificationHandler,
              (DatapathInterface::NotificationInterface * notification),
              (override));
  MOCK_METHOD(absl::Status, SwitchNetwork,
              (uint32_t, const Endpoint&, const NetworkInfo&, int), (override));
  MOCK_METHOD(void, PrepareForTunnelSwitch, (), (override));
  MOCK_METHOD(void, SwitchTunnel, (), (override));
  MOCK_METHOD(absl::Status, SetKeyMaterials, (const TransformParams&),
              (override));
  MOCK_METHOD(void, GetDebugInfo, (DatapathDebugInfo*), (override));
};

class MockSessionNotification : public Session::NotificationInterface {
 public:
  MOCK_METHOD(void, ControlPlaneConnecting, (), (override));
  MOCK_METHOD(void, ControlPlaneConnected, (), (override));
  MOCK_METHOD(void, ControlPlaneFailure, (), (override));
  MOCK_METHOD(void, SessionError, (const absl::Status&), (override));
  MOCK_METHOD(void, PermanentFailure, (const absl::Status&), (override));
  MOCK_METHOD(void, DatapathConnecting, (), (override));
  MOCK_METHOD(void, DatapathConnected, (), (override));
  MOCK_METHOD(void, DatapathDisconnected,
              (const NetworkInfo&, const absl::Status&), (override));
};

class SessionManagerTest : public ::testing::Test {
 public:
  SessionManagerTest()
      : timer_manager_(&mock_timer_), looper_("SessionManagerTest Looper") {}

  void SetUp() override {
    config_.set_zinc_public_signing_key_url("public_key_request");
    config_.set_brass_url("brass_request");
    config_.set_zinc_url("auth_request");

    auto pem = GetPem();
    EXPECT_CALL(mock_http_fetcher_,
                PostJson(UrlMatcher(config_.zinc_public_signing_key_url())))
        .WillRepeatedly([pem] {
          HttpResponse response;
          response.mutable_status()->set_code(200);
          nlohmann::json json_obj;
          json_obj[JsonKeys::kPem] = pem;
          response.set_json_body(utils::JsonToString(json_obj));
          return response;
        });

    EXPECT_CALL(mock_http_fetcher_, PostJson(UrlMatcher(config_.zinc_url())))
        .WillRepeatedly([] {
          HttpResponse response;
          response.mutable_status()->set_code(200);
          nlohmann::json json_obj;
          json_obj[JsonKeys::kBlindedTokenSignature] =
              nlohmann::json::array({"signature"});
          response.set_json_body(utils::JsonToString(json_obj));
          return response;
        });

    EXPECT_CALL(mock_http_fetcher_, PostJson(UrlMatcher(config_.brass_url())))
        .WillRepeatedly([] {
          HttpResponse response;
          response.mutable_status()->set_code(200);
          nlohmann::json json_obj;
          nlohmann::json ppn;
          nlohmann::json ip;
          ip[JsonKeys::kIpv4] = "1.2.3.4";
          ppn[JsonKeys::kUplinkSpi] = 123;
          ppn[JsonKeys::kEgressPointPublicValue] =
              "ZWdyZXNzX3BvaW50X3B1YmxpY192YWx1ZV8xMjM0NTY=";
          ppn[JsonKeys::kServerNonce] = "c2VydmVyX25vbmNlXzEyMw==";
          ppn[JsonKeys::kUserPrivateIp] = nlohmann::json::array({ip});
          ppn[JsonKeys::kEgressPointSockAddr] =
              nlohmann::json::array({"5.6.7.8:123"});
          json_obj[JsonKeys::kPpnDataplane] = ppn;
          response.set_json_body(utils::JsonToString(json_obj));
          return response;
        });

    EXPECT_CALL(mock_oauth_, GetOAuthToken())
        .WillRepeatedly(Return("some_token"));

    EXPECT_CALL(mock_http_fetcher_, LookupDns(_))
        .WillRepeatedly(Return("0.0.0.0"));

    session_manager_ = std::make_unique<SessionManager>(
        config_, &mock_http_fetcher_, &timer_manager_, &mock_vpn_service_,
        &mock_oauth_, &mock_tunnel_manager_, &looper_);

    session_manager_->RegisterNotificationInterface(
        &mock_session_notification_);
  }

  void TearDown() override {
    looper_.Stop();
    looper_.Join();
  }

 protected:
  std::string GetPem() {
    // Some random public string.
    return absl::StrCat(
        "-----BEGIN PUBLIC KEY-----\n",
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv90Xf/NN1lRGBofJQzJf\n",
        "lHvo6GAf25GGQGaMmD9T1ZP71CCbJ69lGIS/6akFBg6ECEHGM2EZ4WFLCdr5byUq\n",
        "GCf4mY4WuOn+AcwzwAoDz9ASIFcQOoPclO7JYdfo2SOaumumdb5S/7FkKJ70TGYW\n",
        "j9aTOYWsCcaojbjGDY/JEXz3BSRIngcgOvXBmV1JokcJ/LsrJD263WE9iUknZDhB\n",
        "K7y4ChjHNqL8yJcw/D8xLNiJtIyuxiZ00p/lOVUInr8C/a2C1UGCgEGuXZAEGAdO\n",
        "NVez52n5TLvQP3hRd4MTi7YvfhezRcA4aXyIDOv+TYi4p+OVTYQ+FMbkgoWBm5bq\n",
        "wQIDAQAB\n", "-----END PUBLIC KEY-----\n");
  }

  KryptonConfig config_;
  MockHttpFetcher mock_http_fetcher_;
  MockTimerInterface mock_timer_;
  TimerManager timer_manager_;
  MockVpnService mock_vpn_service_;
  MockOAuth mock_oauth_;
  MockTunnelManager mock_tunnel_manager_;
  MockSessionNotification mock_session_notification_;
  utils::LooperThread looper_;

  std::unique_ptr<SessionManager> session_manager_;
};

TEST_F(SessionManagerTest, EstablishSessionStartsSession) {
  EXPECT_CALL(mock_vpn_service_, BuildDatapath(_, _, _)).WillOnce([] {
    return new MockDatapath();
  });

  absl::Notification started;
  EXPECT_CALL(mock_tunnel_manager_, DatapathStarted()).WillOnce([&started] {
    started.Notify();
  });
  EXPECT_CALL(mock_tunnel_manager_, DatapathStopped(false));

  session_manager_->EstablishSession(/*restart_count=*/1, &mock_tunnel_manager_,
                                     NetworkInfo());

  ASSERT_TRUE(started.WaitForNotificationWithTimeout(absl::Seconds(1)));

  session_manager_->TerminateSession(false);
}

TEST_F(SessionManagerTest, SecondEstablishSessionTerminatesOldSession) {
  EXPECT_CALL(mock_vpn_service_, BuildDatapath(_, _, _))
      .Times(2)
      .WillRepeatedly([] { return new MockDatapath(); });

  absl::Notification started1;
  absl::Notification started2;
  EXPECT_CALL(mock_tunnel_manager_, DatapathStarted())
      .WillOnce([&started1] { started1.Notify(); })
      .WillOnce([&started2] { started2.Notify(); });
  EXPECT_CALL(mock_tunnel_manager_, DatapathStopped(false)).Times(2);

  session_manager_->EstablishSession(/*restart_count=*/1, &mock_tunnel_manager_,
                                     NetworkInfo());
  ASSERT_TRUE(started1.WaitForNotificationWithTimeout(absl::Seconds(1)));
  session_manager_->EstablishSession(/*restart_count=*/1, &mock_tunnel_manager_,
                                     NetworkInfo());
  ASSERT_TRUE(started2.WaitForNotificationWithTimeout(absl::Seconds(1)));

  session_manager_->TerminateSession(false);
}

TEST_F(SessionManagerTest, SecondTerminateSessionClosesTunnel) {
  EXPECT_CALL(mock_vpn_service_, BuildDatapath(_, _, _)).WillOnce([] {
    return new MockDatapath();
  });

  absl::Notification started;
  EXPECT_CALL(mock_tunnel_manager_, DatapathStarted()).WillOnce([&started] {
    started.Notify();
  });
  EXPECT_CALL(mock_tunnel_manager_, DatapathStopped(false));
  EXPECT_CALL(mock_tunnel_manager_, DatapathStopped(true));

  session_manager_->EstablishSession(/*restart_count=*/1, &mock_tunnel_manager_,
                                     NetworkInfo());
  ASSERT_TRUE(started.WaitForNotificationWithTimeout(absl::Seconds(1)));

  session_manager_->TerminateSession(false);
  session_manager_->TerminateSession(true);
}

TEST_F(SessionManagerTest, ForceTunnelUpdateWithSession) {
  // Set up expectations to create the Session and Datapath
  EXPECT_CALL(mock_vpn_service_, BuildDatapath(_, _, _)).WillOnce([] {
    return new MockDatapath();
  });

  absl::Notification started;
  EXPECT_CALL(mock_tunnel_manager_, DatapathStarted()).WillOnce([&started] {
    started.Notify();
  });

  // Set up expectations for tunnel update
  EXPECT_CALL(mock_tunnel_manager_, IsTunnelActive())
      .WillRepeatedly(Return(true));

  EXPECT_CALL(mock_tunnel_manager_, CreateTunnel(_, true));

  // Create the session and wait for it to complete
  session_manager_->EstablishSession(/*restart_count=*/1, &mock_tunnel_manager_,
                                     NetworkInfo());
  ASSERT_TRUE(started.WaitForNotificationWithTimeout(absl::Seconds(1)));

  // Force tunnel update with a Session created
  session_manager_->ForceTunnelUpdate();

  // Clean up after the test
  session_manager_->TerminateSession(true);
}

TEST_F(SessionManagerTest, ForceTunnelUpdateWithoutSession) {
  EXPECT_CALL(mock_tunnel_manager_, RecreateTunnel());

  session_manager_->ForceTunnelUpdate();
}

TEST_F(SessionManagerTest, SetNetworkWithoutSession) {
  EXPECT_OK(session_manager_->SetNetwork(NetworkInfo()));
}

TEST_F(SessionManagerTest, SetNetworkWithSession) {
  // Set up expectations to start the Session
  auto* mock_datapath = new MockDatapath();

  EXPECT_CALL(mock_vpn_service_, BuildDatapath(_, _, _))
      .WillOnce([&mock_datapath] { return mock_datapath; });

  absl::Notification switch_network_called;
  NetworkInfo initial_network_info;
  initial_network_info.set_network_id(123);
  EXPECT_CALL(*mock_datapath,
              SwitchNetwork(_, _, EqualsProto(initial_network_info), _))
      .WillOnce([&switch_network_called] {
        switch_network_called.Notify();
        return absl::OkStatus();
      });

  session_manager_->EstablishSession(/*restart_count=*/1, &mock_tunnel_manager_,
                                     initial_network_info);

  ASSERT_TRUE(
      switch_network_called.WaitForNotificationWithTimeout(absl::Seconds(1)));

  // Set up expectations for SetNetwork and call it
  NetworkInfo updated_network_info;
  updated_network_info.set_network_id(456);
  EXPECT_CALL(*mock_datapath,
              SwitchNetwork(_, _, EqualsProto(updated_network_info), _));

  EXPECT_OK(session_manager_->SetNetwork(updated_network_info));

  // Clean up after test is done
  session_manager_->TerminateSession(/*forceFailOpen=*/false);
}

}  // namespace
}  // namespace krypton
}  // namespace privacy
