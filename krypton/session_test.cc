// Copyright 2020 Google LLC
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

#include "privacy/net/krypton/session.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <type_traits>

#include "net/proto2/contrib/parse_proto/parse_text_proto.h"
#include "privacy/net/krypton/add_egress_request.h"
#include "privacy/net/krypton/add_egress_response.h"
#include "privacy/net/krypton/auth.h"
#include "privacy/net/krypton/auth_and_sign_response.h"
#include "privacy/net/krypton/crypto/session_crypto.h"
#include "privacy/net/krypton/datapath_interface.h"
#include "privacy/net/krypton/egress_manager.h"
#include "privacy/net/krypton/endpoint.h"
#include "privacy/net/krypton/pal/mock_http_fetcher_interface.h"
#include "privacy/net/krypton/pal/mock_oauth_interface.h"
#include "privacy/net/krypton/pal/mock_timer_interface.h"
#include "privacy/net/krypton/pal/mock_vpn_service_interface.h"
#include "privacy/net/krypton/proto/debug_info.proto.h"
#include "privacy/net/krypton/proto/krypton_config.proto.h"
#include "privacy/net/krypton/proto/network_info.proto.h"
#include "privacy/net/krypton/proto/network_type.proto.h"
#include "privacy/net/krypton/timer_manager.h"
#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/strings/str_replace.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/absl/synchronization/notification.h"
#include "third_party/absl/time/time.h"
#include "third_party/absl/types/optional.h"

namespace privacy {
namespace krypton {
namespace {

using ::testing::_;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::EqualsProto;
using ::testing::Invoke;
using ::testing::InvokeWithoutArgs;
using ::testing::Return;
using ::testing::SetArgPointee;
using ::testing::status::IsOk;
using ::testing::status::StatusIs;

// Checks that a given NetworkInfo is equal to the one passed in.
MATCHER_P(NetworkInfoEquals, expected, "") {
  auto actual = arg;

  if (!actual) {
    return false;
  }

  return expected.network_id() == actual->network_id() &&
         expected.network_type() == actual->network_type();
}

// Mock the Auth.
class MockAuth : public Auth {
 public:
  using Auth::Auth;
  MOCK_METHOD(void, Start, (bool), (override));
  MOCK_METHOD(AuthAndSignResponse, auth_response, (), (const, override));
};

// Mock the Egress Management.
class MockEgressManager : public EgressManager {
 public:
  using EgressManager::EgressManager;
  MOCK_METHOD(absl::StatusOr<AddEgressResponse>, GetEgressSessionDetails, (),
              (const, override));
  MOCK_METHOD(absl::Status, GetEgressNodeForPpnIpSec,
              (const AddEgressRequest::PpnDataplaneRequestParams&), (override));
};

class MockSessionNotification : public Session::NotificationInterface {
 public:
  MOCK_METHOD(void, ControlPlaneConnected, (), (override));
  MOCK_METHOD(void, StatusUpdated, (), (override));
  MOCK_METHOD(void, ControlPlaneDisconnected, (const absl::Status&),
              (override));
  MOCK_METHOD(void, PermanentFailure, (const absl::Status&), (override));
  MOCK_METHOD(void, DatapathConnected, (), (override));
  MOCK_METHOD(void, DatapathDisconnected,
              (const NetworkInfo&, const absl::Status&), (override));
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
              (uint32_t, const Endpoint&, std::optional<NetworkInfo>, int),
              (override));
  MOCK_METHOD(absl::Status, SetKeyMaterials, (const TransformParams&),
              (override));
  MOCK_METHOD(void, GetDebugInfo, (DatapathDebugInfo*), (override));
};

class MockTunnelManager : public TunnelManagerInterface {
 public:
  MOCK_METHOD(absl::Status, Start, (), (override));
  MOCK_METHOD(void, Stop, (), (override));
  MOCK_METHOD(void, SetSafeDisconnectEnabled, (bool), (override));
  MOCK_METHOD(bool, IsSafeDisconnectEnabled, (), (override));
  MOCK_METHOD(void, StartSession, (), (override));
  MOCK_METHOD(absl::Status, EnsureTunnelIsUp, (TunFdData), (override));
  MOCK_METHOD(absl::Status, RecreateTunnelIfNeeded, (), (override));
  MOCK_METHOD(void, TerminateSession, (bool), (override));
  MOCK_METHOD(bool, IsTunnelActive, (), (override));
};

class SessionTest : public ::testing::Test {
 public:
  void SetUp() override {
    EXPECT_CALL(datapath_, RegisterNotificationHandler)
        .WillOnce(
            Invoke([&](DatapathInterface::NotificationInterface* notification) {
              datapath_notification_ = notification;
            }));

    HttpResponse fake_add_egress_http_response;
    fake_add_egress_http_response.mutable_status()->set_code(200);
    fake_add_egress_http_response.mutable_status()->set_message("OK");
    fake_add_egress_http_response.set_json_body(R"string({
      "ppn_dataplane": {
        "user_private_ip": [{
          "ipv4_range": "10.2.2.123/32",
          "ipv6_range": "fec2:0001::3/64"
        }],
        "egress_point_sock_addr": ["64.9.240.165:2153", "[2604:ca00:f001:4::5]:2153"],
        "egress_point_public_value": "a22j+91TxHtS5qa625KCD5ybsyzPR1wkTDWHV2qSQQc=",
        "server_nonce": "Uzt2lEzyvZYzjLAP3E+dAA==",
        "uplink_spi": 1234,
        "expiry": "2020-08-07T01:06:13+00:00"
      }
    })string");

    auto fake_add_egress_response =
        AddEgressResponse::FromProto(fake_add_egress_http_response);
    ASSERT_OK(fake_add_egress_response);
    fake_add_egress_response_ = *fake_add_egress_response;

    session_ = std::make_unique<Session>(
        config_, &auth_, &egress_manager_, &datapath_, &vpn_service_,
        &timer_manager_, &http_fetcher_, &tunnel_manager_, std::nullopt,
        &notification_thread_);
    session_->RegisterNotificationHandler(&notification_);
  }

  void TearDown() override {
    auth_.Stop();
    egress_manager_.Stop();
    tunnel_manager_.Stop();
  }

  void ExpectSuccessfulAuth() {
    EXPECT_CALL(auth_, Start).WillOnce(Invoke([&]() {
      notification_thread_.Post(
          [this] { session_->AuthSuccessful(is_rekey_); });
    }));
    AuthAndSignResponse fake_auth_and_sign_response;
    EXPECT_CALL(auth_, auth_response)
        .WillRepeatedly(Return(fake_auth_and_sign_response));
  }

  void WaitInitial() {
    ASSERT_TRUE(done_.WaitForNotificationWithTimeout(absl::Seconds(3)));
  }

  void WaitForNotifications() {
    absl::Mutex lock;
    absl::CondVar condition;
    absl::MutexLock l(&lock);
    notification_thread_.Post([&lock, &condition] {
      absl::MutexLock l(&lock);
      condition.SignalAll();
    });
    condition.Wait(&lock);
  }

  KryptonConfig config_{proto2::contrib::parse_proto::ParseTextProtoOrDie(
      R"pb(zinc_url: "http://www.example.com/auth"
           brass_url: "http://www.example.com/addegress"
           service_type: "service_type"
           datapath_protocol: BRIDGE
           copper_hostname_suffix: [ 'g-tun.com' ]
           enable_blind_signing: false
           dynamic_mtu_enabled: true)pb")};

  MockSessionNotification notification_;
  MockHttpFetcher http_fetcher_;
  MockOAuth oauth_;
  utils::LooperThread notification_thread_{"Session Test"};
  MockAuth auth_{config_, &http_fetcher_, &oauth_, &notification_thread_};
  MockEgressManager egress_manager_{config_, &http_fetcher_,
                                    &notification_thread_};

  MockDatapath datapath_;
  MockTimerInterface timer_interface_;
  TimerManager timer_manager_{&timer_interface_};

  MockVpnService vpn_service_;
  MockTunnelManager tunnel_manager_;
  std::unique_ptr<Session> session_;
  AddEgressResponse fake_add_egress_response_;
  DatapathInterface::NotificationInterface* datapath_notification_;
  bool is_rekey_ = false;
  absl::Notification done_;
};

// Tests Bridge dataplane and PPN control plane.
class BridgeOnPpnSession : public SessionTest {
 public:
  void SetUp() override {
    config_.set_datapath_protocol(KryptonConfig::BRIDGE);
    EXPECT_CALL(datapath_, RegisterNotificationHandler)
        .WillOnce(
            Invoke([&](DatapathInterface::NotificationInterface* notification) {
              datapath_notification_ = notification;
            }));

    HttpResponse fake_add_egress_http_response;
    fake_add_egress_http_response.mutable_status()->set_code(200);
    fake_add_egress_http_response.mutable_status()->set_message("OK");
    fake_add_egress_http_response.set_json_body(R"string({
      "ppn_dataplane": {
        "user_private_ip": [{
          "ipv4_range": "10.2.2.123/32",
          "ipv6_range": "fec2:0001::3/64"
        }],
        "egress_point_sock_addr": ["64.9.240.165:2153", "[2604:ca00:f001:4::5]:2153"],
        "egress_point_public_value": "a22j+91TxHtS5qa625KCD5ybsyzPR1wkTDWHV2qSQQc=",
        "server_nonce": "Uzt2lEzyvZYzjLAP3E+dAA==",
        "uplink_spi": 123,
        "expiry": "2020-08-07T01:06:13+00:00"
      }
    })string");

    auto fake_add_egress_response =
        AddEgressResponse::FromProto(fake_add_egress_http_response);
    ASSERT_OK(fake_add_egress_response);
    fake_add_egress_response_ = *fake_add_egress_response;

    session_ = std::make_unique<Session>(
        config_, &auth_, &egress_manager_, &datapath_, &vpn_service_,
        &timer_manager_, &http_fetcher_, &tunnel_manager_, std::nullopt,
        &notification_thread_);
    crypto::SessionCrypto remote(config_);
    auto remote_key = remote.GetMyKeyMaterial();
    EXPECT_OK(session_->MutableCryptoTestOnly()->SetRemoteKeyMaterial(
        remote_key.public_value, remote_key.nonce));
    session_->RegisterNotificationHandler(&notification_);
  }

  void ExpectSuccessfulAddEgress() {
    EXPECT_CALL(egress_manager_, GetEgressNodeForPpnIpSec)
        .WillOnce(Invoke(
            [&](const AddEgressRequest::PpnDataplaneRequestParams& params) {
              EXPECT_EQ(params.dataplane_protocol, config_.datapath_protocol());
              notification_thread_.Post(
                  [this]() { session_->EgressAvailable(is_rekey_); });

              return absl::OkStatus();
            }));
    EXPECT_OK(
        egress_manager_.SaveEgressDetailsTestOnly(fake_add_egress_response_));
  }

  void ExpectSuccessfulDatapathInit() {
    EXPECT_CALL(timer_interface_, StartTimer(_, absl::Minutes(5)))
        .WillOnce(Return(absl::OkStatus()));

    EXPECT_CALL(notification_, ControlPlaneConnected());

    EXPECT_CALL(egress_manager_, GetEgressSessionDetails)
        .WillRepeatedly(Invoke([&]() { return fake_add_egress_response_; }));

    EXPECT_CALL(http_fetcher_, LookupDns).WillRepeatedly(Return("0.0.0.0"));

    EXPECT_CALL(datapath_, Start(_, _))
        .WillOnce(::testing::DoAll(
            InvokeWithoutArgs(&done_, &absl::Notification::Notify),
            Return(absl::OkStatus())));
  }

  void StartSessionAndConnectDatapathOnCellular() {
    ExpectSuccessfulAuth();
    ExpectSuccessfulAddEgress();
    ExpectSuccessfulDatapathInit();

    session_->Start();
    WaitInitial();
    EXPECT_CALL(egress_manager_, GetEgressSessionDetails)
        .WillRepeatedly(Invoke([&]() { return fake_add_egress_response_; }));
    EXPECT_CALL(
        tunnel_manager_,
        EnsureTunnelIsUp(EqualsProto(R"pb(tunnel_ip_addresses {
                                            ip_family: IPV4
                                            ip_range: "10.2.2.123"
                                            prefix: 32
                                          }
                                          tunnel_ip_addresses {
                                            ip_family: IPV6
                                            ip_range: "fec2:0001::3"
                                            prefix: 64
                                          }
                                          tunnel_dns_addresses {
                                            ip_family: IPV4
                                            ip_range: "8.8.8.8"
                                            prefix: 32
                                          }
                                          tunnel_dns_addresses {
                                            ip_family: IPV4
                                            ip_range: "8.8.4.4"
                                            prefix: 32
                                          }
                                          tunnel_dns_addresses {
                                            ip_family: IPV6
                                            ip_range: "2001:4860:4860::8888"
                                            prefix: 128
                                          }
                                          tunnel_dns_addresses {
                                            ip_family: IPV6
                                            ip_range: "2001:4860:4860::8844"
                                            prefix: 128
                                          }
                                          is_metered: false
                                          mtu: 1396)pb")));

    NetworkInfo expected_network_info;
    expected_network_info.set_network_id(1234);
    expected_network_info.set_network_type(NetworkType::CELLULAR);
    EXPECT_CALL(
        datapath_,
        SwitchNetwork(123, _, NetworkInfoEquals(expected_network_info), _))
        .WillOnce(Return(absl::OkStatus()));

    NetworkInfo network_info;
    network_info.set_network_id(1234);
    network_info.set_network_type(NetworkType::CELLULAR);
    EXPECT_OK(session_->SetNetwork(network_info));
    WaitForNotifications();
    EXPECT_CALL(notification_, DatapathConnected());

    session_->DatapathEstablished();
    EXPECT_THAT(session_->active_network_info(),
                NetworkInfoEquals(expected_network_info));
  }

  void BringDatapathToConnected() {
    ExpectSuccessfulAuth();
    ExpectSuccessfulAddEgress();
    ExpectSuccessfulDatapathInit();

    session_->Start();

    WaitInitial();
    EXPECT_THAT(session_->LatestStatusTestOnly(), IsOk());

    EXPECT_EQ(session_->state(), Session::State::kConnected);

    EXPECT_CALL(egress_manager_, GetEgressSessionDetails)
        .WillRepeatedly(Invoke([&]() { return fake_add_egress_response_; }));
    EXPECT_CALL(
        tunnel_manager_,
        EnsureTunnelIsUp(EqualsProto(R"pb(tunnel_ip_addresses {
                                            ip_family: IPV4
                                            ip_range: "10.2.2.123"
                                            prefix: 32
                                          }
                                          tunnel_ip_addresses {
                                            ip_family: IPV6
                                            ip_range: "fec2:0001::3"
                                            prefix: 64
                                          }
                                          tunnel_dns_addresses {
                                            ip_family: IPV4
                                            ip_range: "8.8.8.8"
                                            prefix: 32
                                          }
                                          tunnel_dns_addresses {
                                            ip_family: IPV4
                                            ip_range: "8.8.4.4"
                                            prefix: 32
                                          }
                                          tunnel_dns_addresses {
                                            ip_family: IPV6
                                            ip_range: "2001:4860:4860::8888"
                                            prefix: 128
                                          }
                                          tunnel_dns_addresses {
                                            ip_family: IPV6
                                            ip_range: "2001:4860:4860::8844"
                                            prefix: 128
                                          }
                                          is_metered: false
                                          mtu: 1396)pb")));

    NetworkInfo expected_network_info;
    expected_network_info.set_network_type(NetworkType::CELLULAR);
    EXPECT_CALL(
        datapath_,
        SwitchNetwork(123, _, NetworkInfoEquals(expected_network_info), _))
        .WillOnce(Return(absl::OkStatus()));

    NetworkInfo network_info;
    network_info.set_network_type(NetworkType::CELLULAR);
    EXPECT_OK(session_->SetNetwork(network_info));

    EXPECT_CALL(notification_, DatapathConnected());
    session_->DatapathEstablished();
  }
};

TEST_F(SessionTest, AuthenticationFailure) {
  absl::Notification done;
  EXPECT_CALL(auth_, Start).WillOnce(Invoke([&]() {
    notification_thread_.Post(
        [this] { session_->AuthFailure(absl::InternalError("Some error")); });
  }));
  EXPECT_CALL(notification_, ControlPlaneDisconnected(::testing::_))
      .WillOnce(InvokeWithoutArgs(&done, &absl::Notification::Notify));
  session_->Start();
  EXPECT_TRUE(done.WaitForNotificationWithTimeout(absl::Seconds(3)));
  EXPECT_EQ(Session::State::kSessionError, session_->state());
}

TEST_F(SessionTest, AuthenticationPermanentFailure) {
  absl::Notification done;
  EXPECT_CALL(auth_, Start).WillOnce(Invoke([&]() {
    notification_thread_.Post([this] {
      session_->AuthFailure(absl::PermissionDeniedError("Some error"));
    });
  }));

  EXPECT_CALL(notification_, PermanentFailure(::testing::_))
      .WillOnce(InvokeWithoutArgs(&done, &absl::Notification::Notify));

  session_->Start();
  EXPECT_TRUE(done.WaitForNotificationWithTimeout(absl::Seconds(3)));
  EXPECT_EQ(Session::State::kPermanentError, session_->state());
}

// This test assumes Authentication was successful.

TEST_F(BridgeOnPpnSession, DatapathInitFailure) {
  absl::Notification done;
  ExpectSuccessfulAuth();
  ExpectSuccessfulAddEgress();

  EXPECT_CALL(egress_manager_, GetEgressSessionDetails)
      .WillRepeatedly(Invoke([&]() { return fake_add_egress_response_; }));

  EXPECT_CALL(http_fetcher_, LookupDns).WillRepeatedly(Return("0.0.0.0"));
  EXPECT_CALL(datapath_, Start(_, _))
      .WillOnce(::testing::DoAll(
          InvokeWithoutArgs(&done, &absl::Notification::Notify),
          Return(absl::InvalidArgumentError("Initialization error"))));

  session_->Start();
  EXPECT_TRUE(done.WaitForNotificationWithTimeout(absl::Seconds(3)));
  EXPECT_THAT(session_->LatestStatusTestOnly(),
              StatusIs(util::error::INVALID_ARGUMENT, "Initialization error"));

  EXPECT_EQ(session_->state(), Session::State::kSessionError);
}

TEST_F(BridgeOnPpnSession, InitialDatapathEndpointChangeAndNoNetworkAvailable) {
  ExpectSuccessfulAuth();
  ExpectSuccessfulAddEgress();
  ExpectSuccessfulDatapathInit();

  session_->Start();

  WaitInitial();
  EXPECT_CALL(egress_manager_, GetEgressSessionDetails)
      .WillRepeatedly(Invoke([&]() {
        EXPECT_OK(egress_manager_.SaveEgressDetailsTestOnly(
            fake_add_egress_response_));
        return fake_add_egress_response_;
      }));
  EXPECT_CALL(
      tunnel_manager_,
      EnsureTunnelIsUp(EqualsProto(R"pb(tunnel_ip_addresses {
                                          ip_family: IPV4
                                          ip_range: "10.2.2.123"
                                          prefix: 32
                                        }
                                        tunnel_ip_addresses {
                                          ip_family: IPV6
                                          ip_range: "fec2:0001::3"
                                          prefix: 64
                                        }
                                        tunnel_dns_addresses {
                                          ip_family: IPV4
                                          ip_range: "8.8.8.8"
                                          prefix: 32
                                        }
                                        tunnel_dns_addresses {
                                          ip_family: IPV4
                                          ip_range: "8.8.4.4"
                                          prefix: 32
                                        }
                                        tunnel_dns_addresses {
                                          ip_family: IPV6
                                          ip_range: "2001:4860:4860::8888"
                                          prefix: 128
                                        }
                                        tunnel_dns_addresses {
                                          ip_family: IPV6
                                          ip_range: "2001:4860:4860::8844"
                                          prefix: 128
                                        }
                                        is_metered: false
                                        mtu: 1396)pb")));

  NetworkInfo expected_network_info;
  expected_network_info.set_network_type(NetworkType::CELLULAR);
  EXPECT_CALL(
      datapath_,
      SwitchNetwork(123, _, NetworkInfoEquals(expected_network_info), _))
      .WillOnce(Return(absl::OkStatus()));

  NetworkInfo network_info;
  network_info.set_network_type(NetworkType::CELLULAR);

  EXPECT_OK(session_->SetNetwork(network_info));

  EXPECT_CALL(notification_, DatapathConnected());
  session_->DatapathEstablished();

  // No Network available.
  EXPECT_CALL(datapath_, SwitchNetwork(123, _, Eq(std::nullopt), _))
      .WillOnce(Return(absl::OkStatus()));
  EXPECT_OK(session_->SetNetwork(std::nullopt));
}

TEST_F(BridgeOnPpnSession, SwitchNetworkToSameNetworkType) {
  StartSessionAndConnectDatapathOnCellular();

  // Switch network to same type.
  NetworkInfo new_network_info;
  new_network_info.set_network_type(NetworkType::CELLULAR);

  // Expect no tunnel fd change.
  EXPECT_CALL(datapath_,
              SwitchNetwork(123, _, NetworkInfoEquals(new_network_info), _))
      .WillOnce(Return(absl::OkStatus()));

  EXPECT_OK(session_->SetNetwork(new_network_info));
  // Check all the parameters are correct in the session.
  EXPECT_THAT(session_->active_network_info(),
              NetworkInfoEquals(new_network_info));
}

TEST_F(BridgeOnPpnSession, DatapathReattemptFailure) {
  StartSessionAndConnectDatapathOnCellular();

  NetworkInfo expected_network_info;
  expected_network_info.set_network_id(1234);
  expected_network_info.set_network_type(NetworkType::CELLULAR);
  absl::Status status = absl::InternalError("Some error");
  for (int i = 0; i < 4; ++i) {
    // Initial failure
    EXPECT_CALL(timer_interface_, StartTimer(_, absl::Milliseconds(500)))
        .WillOnce(Return(absl::OkStatus()));

    session_->DatapathFailed(status);

    // 2 Attempts on V6, 2 attempts on V4, interlaced.
    // We use modulo because we alternate between the two.
    if (i % 2 == 0) {
      EXPECT_CALL(datapath_,
                  SwitchNetwork(
                      123,
                      Endpoint("[2604:ca00:f001:4::5]:2153",
                               "2604:ca00:f001:4::5", 2153, IPProtocol::kIPv6),
                      NetworkInfoEquals(expected_network_info), _))
          .WillOnce(Return(absl::OkStatus()));
    } else {
      EXPECT_CALL(datapath_,
                  SwitchNetwork(123,
                                Endpoint("64.9.240.165:2153", "64.9.240.165",
                                         2153, IPProtocol::kIPv4),
                                NetworkInfoEquals(expected_network_info), _))
          .WillOnce(Return(absl::OkStatus()));
    }

    session_->AttemptDatapathReconnect();
  }
  // Reattempt not done as we reached the max reattempts.
  EXPECT_CALL(notification_, DatapathDisconnected(_, status));

  session_->DatapathFailed(status);
}

TEST_F(BridgeOnPpnSession, DatapathFailureAndSuccessfulBeforeReattempt) {
  StartSessionAndConnectDatapathOnCellular();

  EXPECT_CALL(timer_interface_, StartTimer(_, absl::Milliseconds(500)))
      .WillOnce(Return(absl::OkStatus()));

  session_->DatapathFailed(absl::InternalError("Some error"));

  // Datapath Successful.
  WaitForNotifications();
  EXPECT_CALL(notification_, DatapathConnected);
  session_->DatapathEstablished();
  EXPECT_EQ(-1, session_->DatapathReattemptTimerIdTestOnly());
  EXPECT_EQ(0, session_->DatapathReattemptCountTestOnly());
}

TEST_F(BridgeOnPpnSession, SwitchNetworkToDifferentNetworkType) {
  StartSessionAndConnectDatapathOnCellular();

  // Switch network to different type.
  NetworkInfo new_network_info;
  new_network_info.set_network_type(NetworkType::WIFI);

  EXPECT_CALL(datapath_,
              SwitchNetwork(123, _, NetworkInfoEquals(new_network_info), _))
      .WillOnce(Return(absl::OkStatus()));

  EXPECT_OK(session_->SetNetwork(new_network_info));
  // Check all the parameters are correct in the session.
  EXPECT_THAT(session_->active_network_info(),
              NetworkInfoEquals(new_network_info));
}

TEST_F(BridgeOnPpnSession, TestEndpointChangeBeforeEstablishingSession) {
  absl::Notification done;
  // Switch network after auth is successful and before session is in
  // connected state.
  EXPECT_CALL(auth_, Start).WillOnce(Invoke([&]() {
    NetworkInfo network_info;
    network_info.set_network_type(NetworkType::CELLULAR);
    notification_thread_.Post([this, network_info]() {
      ASSERT_OK(session_->SetNetwork(network_info));
    });

    notification_thread_.Post([this]() { session_->AuthSuccessful(false); });
  }));
  AuthAndSignResponse fake_auth_and_sign_response;
  EXPECT_CALL(auth_, auth_response)
      .WillRepeatedly(Return(fake_auth_and_sign_response));

  EXPECT_CALL(http_fetcher_, LookupDns).WillRepeatedly(Return("0.0.0.0"));

  ExpectSuccessfulAddEgress();
  EXPECT_CALL(tunnel_manager_, EnsureTunnelIsUp(_));
  EXPECT_CALL(notification_, ControlPlaneConnected());

  EXPECT_CALL(egress_manager_, GetEgressSessionDetails)
      .WillRepeatedly(Invoke([&]() { return fake_add_egress_response_; }));

  EXPECT_CALL(datapath_, Start(_, _))
      .WillOnce(::testing::DoAll(
          InvokeWithoutArgs(&done, &absl::Notification::Notify),
          Return(absl::OkStatus())));

  NetworkInfo expected_network_info;
  expected_network_info.set_network_type(NetworkType::CELLULAR);
  EXPECT_CALL(
      datapath_,
      SwitchNetwork(123, _, NetworkInfoEquals(expected_network_info), _))
      .WillOnce(Return(absl::OkStatus()));

  session_->Start();
  done.WaitForNotificationWithTimeout(absl::Seconds(3));
  EXPECT_CALL(notification_, DatapathConnected());
  session_->DatapathEstablished();
}

TEST_F(SessionTest, PopulatesDebugInfo) {
  session_->Start();

  DatapathDebugInfo datapath_debug_info;
  datapath_debug_info.set_uplink_packets_read(1);
  datapath_debug_info.set_downlink_packets_read(2);
  datapath_debug_info.set_decryption_errors(3);

  EXPECT_CALL(datapath_, GetDebugInfo(_))
      .WillRepeatedly(SetArgPointee<0>(datapath_debug_info));

  SessionDebugInfo debug_info;
  session_->GetDebugInfo(&debug_info);

  EXPECT_THAT(debug_info, EqualsProto(R"pb(
                state: "kInitialized"
                status: "OK"
                successful_rekeys: 0
                network_switches: 1
                datapath: <
                  uplink_packets_read: 1
                  downlink_packets_read: 2
                  decryption_errors: 3
                >
              )pb"));
}

TEST_F(BridgeOnPpnSession, DatapathInitSuccessful) {
  BringDatapathToConnected();
}

TEST_F(BridgeOnPpnSession, DatapathPermanentFailure) {
  BringDatapathToConnected();

  EXPECT_CALL(notification_, DatapathDisconnected(_, _));
  session_->DatapathPermanentFailure(absl::InvalidArgumentError("some error"));
}

TEST_F(BridgeOnPpnSession, TestSetKeyMaterials) {
  ExpectSuccessfulAuth();
  ExpectSuccessfulAddEgress();
  ExpectSuccessfulDatapathInit();

  session_->Start();
  WaitInitial();

  is_rekey_ = true;
  absl::Notification rekey_done;
  ExpectSuccessfulAuth();
  ExpectSuccessfulAddEgress();
  EXPECT_CALL(datapath_, SetKeyMaterials(_))
      .WillOnce(
          DoAll(InvokeWithoutArgs(&rekey_done, &absl::Notification::Notify),
                Return(absl::OkStatus())));
  session_->DoRekey();
  rekey_done.WaitForNotificationWithTimeout(absl::Seconds(3));
  SessionDebugInfo debug_info;
  session_->GetDebugInfo(&debug_info);
}

TEST_F(SessionTest, TestAuthResponseCopperControllerHostname) {
  HttpResponse proto;
  proto.mutable_status()->set_code(200);
  proto.mutable_status()->set_message("OK");
  proto.set_json_body(
      R"string({"copper_controller_hostname":"eu.b.g-tun.com"})string");
  ASSERT_OK_AND_ASSIGN(auto fake_auth_and_sign_response,
                       AuthAndSignResponse::FromProto(proto, config_));
  EXPECT_EQ(fake_auth_and_sign_response.copper_controller_hostname(),
            "eu.b.g-tun.com");
  absl::Notification auth_done;
  EXPECT_CALL(auth_, Start).WillOnce(Invoke([&]() {
    notification_thread_.Post([this, &auth_done] {
      session_->AuthSuccessful(is_rekey_);
      auth_done.Notify();
    });
  }));
  EXPECT_CALL(auth_, auth_response)
      .WillRepeatedly(Return(fake_auth_and_sign_response));

  EXPECT_CALL(http_fetcher_, LookupDns("eu.b.g-tun.com"));
  session_->Start();

  auth_done.WaitForNotificationWithTimeout(absl::Seconds(3));
}

TEST_F(SessionTest, TestEmptyAuthResponseCopperControllerHostname) {
  HttpResponse proto;
  proto.mutable_status()->set_code(200);
  proto.mutable_status()->set_message("OK");
  proto.set_json_body(R"string({"copper_controller_hostname":""})string");
  ASSERT_OK_AND_ASSIGN(auto fake_auth_and_sign_response,
                       AuthAndSignResponse::FromProto(proto, config_));
  EXPECT_EQ(fake_auth_and_sign_response.copper_controller_hostname(), "");
  absl::Notification auth_done;
  EXPECT_CALL(auth_, Start).WillOnce(Invoke([&]() {
    notification_thread_.Post([this, &auth_done] {
      session_->AuthSuccessful(is_rekey_);
      auth_done.Notify();
    });
  }));
  EXPECT_CALL(auth_, auth_response)
      .WillRepeatedly(Return(fake_auth_and_sign_response));

  EXPECT_CALL(http_fetcher_, LookupDns("na.b.g-tun.com"));
  session_->Start();

  auth_done.WaitForNotificationWithTimeout(absl::Seconds(3));
}

TEST(UpdatePathInfoTest, UpdatePathInfoToJsonDefaultValues) {
  ppn::UpdatePathInfo update_path_info;
  auto json_str = ProtoToJsonString(update_path_info);
  std::string expected = R"string(
  {
    "mtu":0,
    "mtu_update_signature":"",
    "sequence_number":0,
    "session_id":0,
    "verification_key":""
  })string";
  absl::StrReplaceAll({{"\n", ""}, {" ", ""}}, &expected);
  EXPECT_EQ(json_str, expected);
}

TEST(UpdatePathInfoTest, UpdatePathInfoToJsonNonDefaultValues) {
  ppn::UpdatePathInfo update_path_info;
  update_path_info.set_session_id(1);
  update_path_info.set_sequence_number(2);
  update_path_info.set_mtu(3);
  update_path_info.set_verification_key("foo");
  update_path_info.set_mtu_update_signature("bar");
  auto json_str = ProtoToJsonString(update_path_info);
  std::string expected = R"string(
  {
    "mtu":3,
    "mtu_update_signature":"YmFy",
    "sequence_number":2,
    "session_id":1,
    "verification_key":"Zm9v"
  })string";
  absl::StrReplaceAll({{"\n", ""}, {" ", ""}}, &expected);
  EXPECT_EQ(json_str, expected);
}

}  // namespace
}  // namespace krypton
}  // namespace privacy
