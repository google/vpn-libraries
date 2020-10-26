// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the );
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an  BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "privacy/net/krypton/session.h"

#include <memory>
#include <string>
#include <type_traits>

#include "net/proto2/contrib/parse_proto/parse_text_proto.h"
#include "privacy/net/krypton/add_egress_request.h"
#include "privacy/net/krypton/add_egress_response.h"
#include "privacy/net/krypton/auth.h"
#include "privacy/net/krypton/auth_and_sign_response.h"
#include "privacy/net/krypton/crypto/session_crypto.h"
#include "privacy/net/krypton/crypto/suite.h"
#include "privacy/net/krypton/datapath_interface.h"
#include "privacy/net/krypton/egress_manager.h"
#include "privacy/net/krypton/pal/http_fetcher_interface.h"
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
#include "third_party/absl/memory/memory.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/absl/time/time.h"
#include "third_party/absl/types/optional.h"
#include "third_party/jsoncpp/value.h"
#include "third_party/jsoncpp/writer.h"

namespace privacy {
namespace krypton {
namespace {

constexpr int kValidTunFd = 0xbeef;
constexpr int kInvalidFd = -1;
constexpr int kValidNetworkFd = 0xbeef + 1;

using ::testing::_;
using ::testing::Eq;
using ::testing::EqualsProto;
using ::testing::Invoke;
using ::testing::Optional;
using ::testing::Return;
using ::testing::status::IsOk;
using ::testing::status::StatusIs;

MATCHER_P(NetworkInfoEquals, network_info, "") {
  auto network_info = arg;

  if (!network_info && !arg) {
    return true;
  }
  return network_info->protected_fd() == arg->protected_fd() &&
         network_info->network_type() == arg->network_type();
}

// Mock the Auth.
class MockAuth : public Auth {
 public:
  using Auth::Auth;
  MOCK_METHOD(void, Start, (bool), (override));
  MOCK_METHOD(std::shared_ptr<AuthAndSignResponse>, auth_response, (),
              (const, override));
};

// Mock the Egress Management.
class MockEgressManager : public EgressManager {
 public:
  using EgressManager::EgressManager;
  MOCK_METHOD(absl::Status, GetEgressNodeForBridge,
              (std::shared_ptr<AuthAndSignResponse>), (override));
  MOCK_METHOD(absl::StatusOr<std::shared_ptr<AddEgressResponse>>,
              GetEgressSessionDetails, (), (const, override));
  MOCK_METHOD(absl::Status, GetEgressNodeForPpnIpSec,
              (const AddEgressRequest::PpnDataplaneRequestParams&), (override));
  MOCK_METHOD(bool, is_ppn, (), (const, override));
};

class MockHttpFetcherInterface : public HttpFetcherInterface {
 public:
  MOCK_METHOD(std::string, PostJson,
              (absl::string_view, const Json::Value&, const Json::Value&),
              (override));
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
              (std::shared_ptr<AddEgressResponse>, const BridgeTransformParams&,
               CryptoSuite),
              (override));
  MOCK_METHOD(void, Stop, (), (override));
  MOCK_METHOD(bool, is_running, (), (const, override));
  MOCK_METHOD(void, RegisterNotificationHandler,
              (DatapathInterface::NotificationInterface * notification),
              (override));
  MOCK_METHOD(absl::Status, SwitchNetwork,
              (bool, uint32, const std::vector<std::string>&,
               absl::optional<NetworkInfo>, int, int),
              (override));
  MOCK_METHOD(absl::Status, Rekey, (const std::string&, const std::string&),
              (override));
};

class SessionTest : public ::testing::Test {
 public:
  void SetUp() override {
    EXPECT_CALL(datapath_, RegisterNotificationHandler)
        .WillOnce(
            Invoke([&](DatapathInterface::NotificationInterface* notification) {
              datapath_notification_ = notification;
            }));
    fake_auth_and_sign_response_ = std::make_shared<AuthAndSignResponse>();
    fake_add_egress_response_ = std::make_shared<AddEgressResponse>();

    ASSERT_OK(fake_add_egress_response_->DecodeFromJsonObject(R"string(
  {
    "http": {
      "status":{
        "code": 200,
        "message" : "OK"
      }
    },
    "json_body": {
       "bridge": {
          "session_id": 1234,
          "error": "no error",
          "session_token": "A89C39",
          "client_crypto_key": "some_client_crypto_key",
          "data_plane_sock_addrs":["64.9.240.165:2153", "[2604:ca00:f001:4::5]:2153"],
          "server_crypto_key": "some_server_crypto_key",
          "ip_ranges":["10.2.2.123/32","fec2:0001::3/64"],
          "control_plane_sock_addrs": ["10.2.2.125","fec2:0003"]
       }
    }
  })string"));
    session_ = absl::make_unique<Session>(
        &auth_, &egress_manager_, &datapath_, &vpn_service_, &timer_manager_,
        absl::nullopt, &config_, &notification_thread_);
    session_->RegisterNotificationHandler(&notification_);
  }

  void TearDown() override {
    auth_.Stop();
    egress_manager_.Stop();
  }

  virtual void ExpectSuccessfulAddEgress() {
    EXPECT_CALL(egress_manager_, GetEgressNodeForBridge)
        .WillOnce(
            Invoke([&](std::shared_ptr<AuthAndSignResponse> /*auth_response*/) {
              session_->EgressAvailable(false);
              return absl::OkStatus();
            }));
    EXPECT_OK(
        egress_manager_.SaveEgressDetailsTestOnly(fake_add_egress_response_));
  }

  void ExpectSuccessfulAuth() {
    EXPECT_CALL(auth_, Start).WillOnce(Invoke([&]() {
      session_->AuthSuccessful(is_rekey_);
    }));
    EXPECT_CALL(auth_, auth_response)
        .WillRepeatedly(Return(fake_auth_and_sign_response_));
  }

  virtual void ExpectSuccessfulDatapathInit() {
    EXPECT_CALL(timer_interface_, StartTimer(_, absl::Minutes(5)))
        .WillOnce(Return(absl::OkStatus()));

    EXPECT_CALL(notification_, ControlPlaneConnected());

    EXPECT_CALL(egress_manager_, GetEgressSessionDetails)
        .WillRepeatedly(Invoke([&]() { return fake_add_egress_response_; }));

    EXPECT_CALL(datapath_, Start(fake_add_egress_response_, _, _))
        .WillOnce(Return(absl::OkStatus()));
  }

  void StartSessionAndConnectDatapathOnCellular() {
    ExpectSuccessfulAuth();
    ExpectSuccessfulAddEgress();
    ExpectSuccessfulDatapathInit();

    session_->Start();
    network_fd_counter_ += 1;
    EXPECT_CALL(egress_manager_, GetEgressSessionDetails)
        .WillRepeatedly(Invoke([&]() { return fake_add_egress_response_; }));
    EXPECT_CALL(vpn_service_,
                CreateTunFd(EqualsProto(R"pb(tunnel_ip_addresses {
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
                                               ip_range: "8.8.8.4"
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
                                             is_metered: false)pb")))
        .WillOnce(Return(++tun_fd_counter_));
    EXPECT_CALL(vpn_service_,
                CreateNetworkFd(EqualsProto(R"pb(network_id: 1234
                                                 network_type: CELLULAR)pb")))
        .WillOnce(Return(network_fd_counter_));

    NetworkInfo expected_network_info;
    expected_network_info.set_network_id(1234);
    expected_network_info.set_network_type(NetworkType::CELLULAR);
    EXPECT_CALL(
        datapath_,
        SwitchNetwork(false, 1234, _, NetworkInfoEquals(expected_network_info),
                      _, tun_fd_counter_))
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
    EXPECT_THAT(session_->active_tun_fd(), Optional(tun_fd_counter_));
    EXPECT_THAT(session_->previous_tun_fd(), Eq(absl::nullopt));
  }

  void WaitForNotifications() {
    absl::Mutex lock;
    absl::CondVar condition;
    absl::MutexLock l(&lock);
    notification_thread_.Post([&condition] { condition.SignalAll(); });
    condition.Wait(&lock);
  }

  KryptonConfig config_{
      proto2::contrib::parse_proto::ParseTextProtoOrDie(
          R"pb(zinc_url: "http://www.example.com/auth"
               service_type: "service_type")pb")};

  int tun_fd_counter_ = kValidTunFd;  // Starting value of tun fd.
  int network_fd_counter_ = kValidTunFd + 1000;
  MockSessionNotification notification_;
  MockHttpFetcherInterface http_fetcher_;
  MockOAuth oauth_;
  utils::LooperThread notification_thread_{"Session Test"};
  MockAuth auth_{&config_, &http_fetcher_, &oauth_, &notification_thread_};
  MockEgressManager egress_manager_{"http://www.example.com/addegress",
                                    &http_fetcher_, &notification_thread_};

  MockDatapath datapath_;
  MockTimerInterface timer_interface_;
  TimerManager timer_manager_{&timer_interface_};

  MockVpnService vpn_service_;
  std::unique_ptr<Session> session_;
  std::shared_ptr<AuthAndSignResponse> fake_auth_and_sign_response_;
  std::shared_ptr<AddEgressResponse> fake_add_egress_response_;
  DatapathInterface::NotificationInterface* datapath_notification_;
  bool is_rekey_ = false;
};

TEST_F(SessionTest, AuthenticationFailure) {
  EXPECT_CALL(auth_, Start).WillOnce(Invoke([&]() {
    session_->AuthFailure(absl::InternalError("Some error"));
  }));
  EXPECT_CALL(notification_, ControlPlaneDisconnected(::testing::_));
  session_->Start();
  EXPECT_EQ(Session::State::kSessionError, session_->state());
}

TEST_F(SessionTest, AuthenticationPermanentFailure) {
  EXPECT_CALL(auth_, Start).WillOnce(Invoke([&]() {
    session_->AuthFailure(absl::PermissionDeniedError("Some error"));
  }));
  EXPECT_CALL(notification_, PermanentFailure(::testing::_));
  session_->Start();
  EXPECT_EQ(Session::State::kPermanentError, session_->state());
}

// This test assumes Authentication was successful.
TEST_F(SessionTest, AddEgressFailure) {
  ExpectSuccessfulAuth();

  EXPECT_CALL(egress_manager_, GetEgressNodeForBridge)
      .WillOnce(Invoke([&](std::shared_ptr<AuthAndSignResponse>) {
        return absl::NotFoundError("Add Egress Failure");
      }));
  EXPECT_CALL(notification_, ControlPlaneDisconnected(::testing::_));
  session_->Start();

  EXPECT_THAT(session_->latest_status(),
              StatusIs(absl::StatusCode::kNotFound, "Add Egress Failure"));
}

TEST_F(SessionTest, DatapathInitFailure) {
  ExpectSuccessfulAuth();
  ExpectSuccessfulAddEgress();

  EXPECT_CALL(egress_manager_, GetEgressSessionDetails)
      .WillRepeatedly(Invoke([&]() { return fake_add_egress_response_; }));

  EXPECT_CALL(datapath_, Start(fake_add_egress_response_, _, _))
      .WillOnce(Return(absl::InvalidArgumentError("Initialization error")));

  session_->Start();

  EXPECT_THAT(session_->latest_status(),
              StatusIs(util::error::INVALID_ARGUMENT, "Initialization error"));

  EXPECT_EQ(session_->state(), Session::State::kSessionError);
}

TEST_F(SessionTest, DatapathInitSuccessful) {
  ExpectSuccessfulAuth();
  ExpectSuccessfulAddEgress();
  ExpectSuccessfulDatapathInit();

  session_->Start();

  EXPECT_THAT(session_->latest_status(), IsOk());

  EXPECT_EQ(session_->state(), Session::State::kConnected);
}

TEST_F(SessionTest, RekeyUnavailableForBridge) {
  ExpectSuccessfulAuth();
  ExpectSuccessfulAddEgress();
  ExpectSuccessfulDatapathInit();

  session_->Start();

  EXPECT_THAT(
      session_->RekeyTestOnly(),
      StatusIs(
          absl::StatusCode::kFailedPrecondition,
          "Rekey is not needed as the session is not PpnDataplane protocol"));
}

TEST_F(SessionTest, InitialDatapathEndpointChangeAndNoNetworkAvailable) {
  ExpectSuccessfulAuth();
  ExpectSuccessfulAddEgress();
  ExpectSuccessfulDatapathInit();

  session_->Start();

  EXPECT_CALL(egress_manager_, GetEgressSessionDetails)
      .WillRepeatedly(Invoke([&]() {
        EXPECT_OK(egress_manager_.SaveEgressDetailsTestOnly(
            fake_add_egress_response_));
        return fake_add_egress_response_;
      }));
  EXPECT_CALL(vpn_service_,
              CreateTunFd(EqualsProto(R"pb(tunnel_ip_addresses {
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
                                             ip_range: "8.8.8.4"
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
                                           is_metered: false)pb")))
      .WillOnce(Return(++tun_fd_counter_));

  EXPECT_CALL(vpn_service_,
              CreateNetworkFd(EqualsProto(R"pb(network_type: CELLULAR)pb")))
      .WillOnce(Return(tun_fd_counter_));
  NetworkInfo expected_network_info;
  expected_network_info.set_protected_fd(tun_fd_counter_);
  expected_network_info.set_network_type(NetworkType::CELLULAR);
  EXPECT_CALL(datapath_, SwitchNetwork(false, 1234, _,
                                       NetworkInfoEquals(expected_network_info),
                                       _, tun_fd_counter_))
      .WillOnce(Return(absl::OkStatus()));

  NetworkInfo network_info;
  network_info.set_network_type(NetworkType::CELLULAR);

  EXPECT_OK(session_->SetNetwork(network_info));

  EXPECT_CALL(notification_, DatapathConnected());
  session_->DatapathEstablished();

  // No Network available.
  EXPECT_CALL(datapath_, SwitchNetwork(false, 1234, _, Eq(absl::nullopt), _,
                                       tun_fd_counter_))
      .WillOnce(Return(absl::OkStatus()));
  EXPECT_OK(session_->SetNetwork(absl::nullopt));
}

TEST_F(SessionTest, SwitchNetworkToSameNetworkType) {
  StartSessionAndConnectDatapathOnCellular();

  // Switch network to same type.
  network_fd_counter_ += 1;
  NetworkInfo new_network_info;
  new_network_info.set_network_type(NetworkType::CELLULAR);

  EXPECT_CALL(vpn_service_,
              CreateNetworkFd(EqualsProto(R"pb(network_type: CELLULAR)pb")))
      .WillOnce(Return(network_fd_counter_));
  // Expect no tunnel fd change.
  EXPECT_CALL(datapath_,
              SwitchNetwork(false, 1234, _, NetworkInfoEquals(new_network_info),
                            _, tun_fd_counter_))
      .WillOnce(Return(absl::OkStatus()));

  EXPECT_OK(session_->SetNetwork(new_network_info));
  // Check all the parameters are correct in the session.
  EXPECT_THAT(session_->active_network_info(),
              NetworkInfoEquals(new_network_info));
  EXPECT_THAT(session_->active_tun_fd(), Optional(tun_fd_counter_));
  EXPECT_THAT(session_->previous_tun_fd(), Eq(absl::nullopt));
}

TEST_F(SessionTest, DatapathReattemptFailure) {
  StartSessionAndConnectDatapathOnCellular();

  EXPECT_CALL(egress_manager_, is_ppn).WillRepeatedly(Return(false));
  NetworkInfo expected_network_info;
  expected_network_info.set_network_id(1234);
  expected_network_info.set_protected_fd(network_fd_counter_);
  expected_network_info.set_network_type(NetworkType::CELLULAR);
  absl::Status status = absl::InternalError("Some error");
  for (int i = 0; i < 3; ++i) {
    // Initial failure
    EXPECT_CALL(timer_interface_, StartTimer(_, absl::Milliseconds(500)))
        .WillOnce(Return(absl::OkStatus()));

    session_->DatapathFailed(status, network_fd_counter_);

    EXPECT_CALL(vpn_service_,
                CreateNetworkFd(EqualsProto(R"pb(protected_fd: 49880
                                                 network_type: CELLULAR
                                                 network_id: 1234)pb")))
        .WillOnce(Return(network_fd_counter_));

    // 2 Attempts on V6, 2 attempts on V4.  V6 preferred over v4.
    if (i < 2) {
      EXPECT_CALL(
          datapath_,
          SwitchNetwork(
              false, 1234, ::testing::ElementsAre("[2604:ca00:f001:4::5]:2153"),
              NetworkInfoEquals(expected_network_info), _, tun_fd_counter_))
          .WillOnce(Return(absl::OkStatus()));
    } else {
      EXPECT_CALL(datapath_,
                  SwitchNetwork(false, 1234,
                                ::testing::ElementsAre("64.9.240.165:2153"),
                                NetworkInfoEquals(expected_network_info), _,
                                tun_fd_counter_))
          .WillOnce(Return(absl::OkStatus()));
    }

    session_->AttemptDatapathReconnect();
  }
  // Reattempt not done as we reached the max reattempts.
  EXPECT_CALL(notification_, DatapathDisconnected(_, status));

  session_->DatapathFailed(status, network_fd_counter_);
}

TEST_F(SessionTest, DatapathFailureAndSuccessfulBeforeReattempt) {
  StartSessionAndConnectDatapathOnCellular();

  EXPECT_CALL(timer_interface_, StartTimer(_, absl::Milliseconds(500)))
      .WillOnce(Return(absl::OkStatus()));

  session_->DatapathFailed(absl::InternalError("Some error"),
                           network_fd_counter_);

  // Datapath Successful.
  WaitForNotifications();
  EXPECT_CALL(notification_, DatapathConnected);
  session_->DatapathEstablished();
  EXPECT_EQ(-1, session_->DatapathReattemptTimerIdTestOnly());
  EXPECT_EQ(0, session_->DatapathReattemptCountTestOnly());
}

TEST_F(SessionTest, SwitchNetworkToDifferentNetworkType) {
  StartSessionAndConnectDatapathOnCellular();

  // Switch network to different type.
  network_fd_counter_ += 1;
  NetworkInfo new_network_info;
  new_network_info.set_protected_fd(network_fd_counter_);
  new_network_info.set_network_type(NetworkType::WIFI);

  EXPECT_CALL(vpn_service_,
              CreateNetworkFd(EqualsProto(R"pb(protected_fd: 49881
                                               network_type: WIFI)pb")))
      .WillOnce(Return(network_fd_counter_));
  EXPECT_CALL(datapath_,
              SwitchNetwork(false, 1234, _, NetworkInfoEquals(new_network_info),
                            _, tun_fd_counter_))
      .WillOnce(Return(absl::OkStatus()));

  EXPECT_OK(session_->SetNetwork(new_network_info));
  // Check all the parameters are correct in the session.
  EXPECT_THAT(session_->active_network_info(),
              NetworkInfoEquals(new_network_info));
  EXPECT_THAT(session_->active_tun_fd(), Optional(tun_fd_counter_));
}

TEST_F(SessionTest, TestEndpointChangeBeforeEstablishingSession) {
  // Switch network after auth is successful and before session is in
  // connected state.
  EXPECT_CALL(auth_, Start).WillOnce(Invoke([&]() {
    NetworkInfo network_info;
    network_info.set_protected_fd(kValidNetworkFd);
    network_info.set_network_type(NetworkType::CELLULAR);
    ASSERT_OK(session_->SetNetwork(network_info));
    session_->AuthSuccessful(false);
  }));
  EXPECT_CALL(auth_, auth_response)
      .WillRepeatedly(Return(fake_auth_and_sign_response_));

  ExpectSuccessfulAddEgress();
  EXPECT_CALL(vpn_service_, CreateTunFd(_)).WillOnce(Return(++tun_fd_counter_));
  EXPECT_CALL(notification_, ControlPlaneConnected());

  EXPECT_CALL(egress_manager_, GetEgressSessionDetails)
      .WillRepeatedly(Invoke([&]() { return fake_add_egress_response_; }));

  EXPECT_CALL(datapath_, Start(fake_add_egress_response_, _, _))
      .WillOnce(Return(absl::OkStatus()));

  EXPECT_CALL(vpn_service_,
              CreateNetworkFd(EqualsProto(R"pb(protected_fd: 48880
                                               network_type: CELLULAR)pb")))
      .WillOnce(Return(network_fd_counter_));
  NetworkInfo expected_network_info;
  expected_network_info.set_protected_fd(kValidNetworkFd);
  expected_network_info.set_network_type(NetworkType::CELLULAR);
  EXPECT_CALL(datapath_, SwitchNetwork(false, 1234, _,
                                       NetworkInfoEquals(expected_network_info),
                                       _, tun_fd_counter_))
      .WillOnce(Return(absl::OkStatus()));

  session_->Start();

  EXPECT_CALL(notification_, DatapathConnected());
  session_->DatapathEstablished();
}

TEST_F(SessionTest, PopulatesDebugInfo) {
  session_->Start();

  SessionDebugInfo debug_info;
  session_->GetDebugInfo(&debug_info);

  EXPECT_THAT(debug_info, EqualsProto(R"pb(
                state: "kInitialized"
                status: "OK"
                successful_rekeys: 0
                network_switches: 1
              )pb"));
}

// Tests Bridge dataplane and PPN control plane.
class BridgeOnPpnSession : public SessionTest {
 public:
  void SetUp() override {
    config_.set_bridge_over_ppn(true);
    EXPECT_CALL(datapath_, RegisterNotificationHandler)
        .WillOnce(
            Invoke([&](DatapathInterface::NotificationInterface* notification) {
              datapath_notification_ = notification;
            }));
    fake_auth_and_sign_response_ = std::make_shared<AuthAndSignResponse>();
    fake_add_egress_response_ = std::make_shared<AddEgressResponse>();

    ASSERT_OK(fake_add_egress_response_->DecodeFromJsonObject(R"string(
  {
    "http": {
      "status":{
        "code": 200,
        "message" : "OK"
      }
    },
    "json_body": {
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
    }
  })string"));
    session_ = absl::make_unique<Session>(
        &auth_, &egress_manager_, &datapath_, &vpn_service_, &timer_manager_,
        absl::nullopt, &config_, &notification_thread_);
    crypto::SessionCrypto remote;
    auto remote_key = remote.GetMyKeyMaterial();
    EXPECT_OK(session_->MutableCryptoTestOnly()->SetRemoteKeyMaterial(
        remote_key.public_value, remote_key.nonce));
    session_->RegisterNotificationHandler(&notification_);
  }

  void ExpectSuccessfulAddEgress() override {
    EXPECT_CALL(egress_manager_, GetEgressNodeForPpnIpSec)
        .WillOnce(Invoke(
            [&](const AddEgressRequest::PpnDataplaneRequestParams& /*params*/) {
              session_->EgressAvailable(is_rekey_);
              return absl::OkStatus();
            }));
    EXPECT_OK(
        egress_manager_.SaveEgressDetailsTestOnly(fake_add_egress_response_));
  }

  void ExpectSuccessfulDatapathInit() override {
    EXPECT_CALL(timer_interface_, StartTimer(_, absl::Minutes(5)))
        .WillOnce(Return(absl::OkStatus()));

    EXPECT_CALL(notification_, ControlPlaneConnected());

    EXPECT_CALL(egress_manager_, GetEgressSessionDetails)
        .WillRepeatedly(Invoke([&]() { return fake_add_egress_response_; }));

    EXPECT_CALL(datapath_, Start(fake_add_egress_response_, _, _))
        .WillOnce(Return(absl::OkStatus()));
  }

  void BringDatapathToConnected() {
    ExpectSuccessfulAuth();
    ExpectSuccessfulAddEgress();
    ExpectSuccessfulDatapathInit();

    session_->Start();

    EXPECT_THAT(session_->latest_status(), IsOk());

    EXPECT_EQ(session_->state(), Session::State::kConnected);
    EXPECT_CALL(egress_manager_, is_ppn)
        .WillRepeatedly(::testing::Return(true));

    EXPECT_CALL(egress_manager_, GetEgressSessionDetails)
        .WillRepeatedly(Invoke([&]() { return fake_add_egress_response_; }));
    EXPECT_CALL(vpn_service_,
                CreateTunFd(EqualsProto(R"pb(tunnel_ip_addresses {
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
                                               ip_range: "8.8.8.4"
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
                                             is_metered: false)pb")))
        .WillOnce(Return(++tun_fd_counter_));

    EXPECT_CALL(vpn_service_,
                CreateNetworkFd(EqualsProto(R"pb(network_type: CELLULAR)pb")))
        .WillOnce(Return(tun_fd_counter_));
    NetworkInfo expected_network_info;
    expected_network_info.set_protected_fd(tun_fd_counter_);
    expected_network_info.set_network_type(NetworkType::CELLULAR);
    EXPECT_CALL(
        datapath_,
        SwitchNetwork(true, 123, _, NetworkInfoEquals(expected_network_info), _,
                      tun_fd_counter_))
        .WillOnce(Return(absl::OkStatus()));

    NetworkInfo network_info;
    network_info.set_network_type(NetworkType::CELLULAR);
    EXPECT_OK(session_->SetNetwork(network_info));

    EXPECT_CALL(notification_, DatapathConnected());
    session_->DatapathEstablished();
  }
};

TEST_F(BridgeOnPpnSession, DatapathInitSuccessful) {
  BringDatapathToConnected();
}

TEST_F(BridgeOnPpnSession, DatapathPermanentFailure) {
  BringDatapathToConnected();

  EXPECT_CALL(notification_, DatapathDisconnected(_, _));
  session_->DatapathPermanentFailure(absl::InvalidArgumentError("some error"));
}

TEST_F(BridgeOnPpnSession, TestRekey) {
  ExpectSuccessfulAuth();
  ExpectSuccessfulAddEgress();
  ExpectSuccessfulDatapathInit();

  session_->Start();
  EXPECT_CALL(egress_manager_, is_ppn).WillRepeatedly(::testing::Return(true));
  is_rekey_ = true;
  ExpectSuccessfulAuth();
  ExpectSuccessfulAddEgress();
  EXPECT_CALL(datapath_, Rekey(_, _)).WillOnce(Return(absl::OkStatus()));
  session_->DoRekey();
  SessionDebugInfo debug_info;
  session_->GetDebugInfo(&debug_info);
  EXPECT_EQ(1, debug_info.successful_rekeys());
}
}  // namespace
}  // namespace krypton
}  // namespace privacy
