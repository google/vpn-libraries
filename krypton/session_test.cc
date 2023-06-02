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
#include <utility>

#include "google/protobuf/timestamp.proto.h"
#include "net/proto2/contrib/parse_proto/parse_text_proto.h"
#include "privacy/net/common/proto/get_initial_data.proto.h"
#include "privacy/net/common/proto/public_metadata.proto.h"
#include "privacy/net/common/proto/update_path_info.proto.h"
#include "privacy/net/krypton/add_egress_request.h"
#include "privacy/net/krypton/add_egress_response.h"
#include "privacy/net/krypton/auth.h"
#include "privacy/net/krypton/auth_and_sign_response.h"
#include "privacy/net/krypton/datapath_interface.h"
#include "privacy/net/krypton/egress_manager.h"
#include "privacy/net/krypton/endpoint.h"
#include "privacy/net/krypton/json_keys.h"
#include "privacy/net/krypton/pal/mock_http_fetcher_interface.h"
#include "privacy/net/krypton/pal/mock_oauth_interface.h"
#include "privacy/net/krypton/pal/mock_timer_interface.h"
#include "privacy/net/krypton/pal/mock_vpn_service_interface.h"
#include "privacy/net/krypton/pal/packet.h"
#include "privacy/net/krypton/proto/debug_info.proto.h"
#include "privacy/net/krypton/proto/http_fetcher.proto.h"
#include "privacy/net/krypton/proto/krypton_config.proto.h"
#include "privacy/net/krypton/proto/network_info.proto.h"
#include "privacy/net/krypton/proto/network_type.proto.h"
#include "privacy/net/krypton/proto/tun_fd_data.proto.h"
#include "privacy/net/krypton/timer_manager.h"
#include "privacy/net/krypton/tunnel_manager_interface.h"
#include "privacy/net/krypton/utils/json_util.h"
#include "privacy/net/krypton/utils/looper.h"
#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"
#include "third_party/absl/cleanup/cleanup.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/strings/str_replace.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/absl/synchronization/mutex.h"
#include "third_party/absl/synchronization/notification.h"
#include "third_party/absl/time/time.h"
#include "third_party/absl/types/optional.h"
#include "third_party/json/include/nlohmann/json.hpp"
#include "util/task/status.h"

namespace privacy {
namespace krypton {
namespace {

using ::proto2::contrib::parse_proto::ParseTextProtoOrDie;
using ::testing::_;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::EqualsProto;
using ::testing::HasSubstr;
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
  MOCK_METHOD(ppn::GetInitialDataResponse, initial_data_response, (),
              (const, override));
  MOCK_METHOD(void, RegisterNotificationHandler, (Auth::NotificationInterface*),
              (override));
};

// Mock the Egress Management.
class MockEgressManager : public EgressManager {
 public:
  using EgressManager::EgressManager;
  MOCK_METHOD(absl::StatusOr<AddEgressResponse>, GetEgressSessionDetails, (),
              (const, override));
  MOCK_METHOD(absl::Status, GetEgressNodeForPpnIpSec,
              (const AddEgressRequest::PpnDataplaneRequestParams&), (override));
  MOCK_METHOD(void, RegisterNotificationHandler,
              (EgressManager::NotificationInterface*), (override));
};

class MockSessionNotification : public Session::NotificationInterface {
 public:
  MOCK_METHOD(void, ControlPlaneConnected, (), (override));
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
  MOCK_METHOD(void, PrepareForTunnelSwitch, (), (override));
  MOCK_METHOD(void, SwitchTunnel, (), (override));
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
  MOCK_METHOD(void, DatapathStarted, (), (override));
  MOCK_METHOD(absl::Status, EnsureTunnelIsUp, (TunFdData), (override));
  MOCK_METHOD(absl::Status, RecreateTunnelIfNeeded, (), (override));
  MOCK_METHOD(void, DatapathStopped, (bool), (override));
  MOCK_METHOD(bool, IsTunnelActive, (), (override));
};

// Tests Bridge dataplane and PPN control plane.
class SessionTest : public ::testing::Test {
 public:
  void SetUp() override {
    auto datapath = std::make_unique<MockDatapath>();
    datapath_ = datapath.get();

    EXPECT_CALL(*datapath_, RegisterNotificationHandler)
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

    EXPECT_CALL(auth_, RegisterNotificationHandler)
        .WillOnce([this](Auth::NotificationInterface* notification) {
          auth_notification_ = notification;
        });

    EXPECT_CALL(egress_manager_, RegisterNotificationHandler)
        .WillOnce([this](EgressManager::NotificationInterface* notification) {
          egress_notification_ = notification;
        });

    session_ = std::make_unique<Session>(
        config_, &auth_, &egress_manager_, std::move(datapath), &vpn_service_,
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
      notification_thread_.Post([this] {
        ASSERT_NE(auth_notification_, nullptr);
        auth_notification_->AuthSuccessful(is_rekey_);
      });
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

  ppn::GetInitialDataResponse CreateGetInitialDataResponse() {
    // sig_hash_type = HashType::AT_HASH_TYPE_SHA256
    // mask_gen_function = MaskGenFunction::AT_MGF_SHA256
    // message_mask_type = MessageMaskType::AT_MESSAGE_MASK_CONCAT
    ppn::GetInitialDataResponse response = ParseTextProtoOrDie(R"pb(
      at_public_metadata_public_key: {
        use_case: "test",
        key_version: 2,
        serialized_public_key: "-----BEGIN PUBLIC KEY-----\n"
                               "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv90Xf/NN1lRGBofJQzJf\n"
                               "lHvo6GAf25GGQGaMmD9T1ZP71CCbJ69lGIS/6akFBg6ECEHGM2EZ4WFLCdr5byUq\n"
                               "GCf4mY4WuOn+AcwzwAoDz9ASIFcQOoPclO7JYdfo2SOaumumdb5S/7FkKJ70TGYW\n"
                               "j9aTOYWsCcaojbjGDY/JEXz3BSRIngcgOvXBmV1JokcJ/LsrJD263WE9iUknZDhB\n"
                               "K7y4ChjHNqL8yJcw/D8xLNiJtIyuxiZ00p/lOVUInr8C/a2C1UGCgEGuXZAEGAdO\n"
                               "NVez52n5TLvQP3hRd4MTi7YvfhezRcA4aXyIDOv+TYi4p+OVTYQ+FMbkgoWBm5bq\n"
                               "wQIDAQAB\n-----END PUBLIC KEY-----\n",
        expiration_time: { seconds: 900, nanos: 0 },
        key_validity_start_time: { seconds: 900, nanos: 0 },
        sig_hash_type: 2,
        mask_gen_function: 2,
        salt_length: 2,
        key_size: 2,
        message_mask_type: 2,
        message_mask_size: 2
      },
      public_metadata_info: {
        public_metadata: {
          exit_location: { country: "US", city_geo_id: "us_ca_san_diego" },
          service_type: "service_type",
          expiration: { seconds: 900, nanos: 0 },
        },
        validation_version: 1
      },
      attestation: { attestation_nonce: "some_nonce" }
    )pb");
    return response;
  }

  void ExpectSuccessfulProvision() {
    ExpectSuccessfulAuth();
    ExpectSuccessfulAddEgress();
  }

  void ExpectSuccessfulAddEgress() {
    HttpResponse initial_data_proto;
    initial_data_proto.mutable_status()->set_code(200);
    initial_data_proto.mutable_status()->set_message("OK");
    initial_data_proto.set_proto_body(
        CreateGetInitialDataResponse().SerializeAsString());

    ASSERT_OK_AND_ASSIGN(auto fake_initial_data_response,
                         DecodeGetInitialDataResponse(initial_data_proto));
    EXPECT_CALL(auth_, initial_data_response)
        .WillOnce(Return(fake_initial_data_response));

    EXPECT_CALL(egress_manager_, GetEgressNodeForPpnIpSec)
        .WillOnce(Invoke(
            [&](const AddEgressRequest::PpnDataplaneRequestParams& params) {
              EXPECT_EQ(params.dataplane_protocol, config_.datapath_protocol());
              CheckPublicMetadataParams(params);
              notification_thread_.Post([this]() {
                ASSERT_NE(egress_notification_, nullptr);
                egress_notification_->EgressAvailable(is_rekey_);
              });

              return absl::OkStatus();
            }));
    EXPECT_OK(
        egress_manager_.SaveEgressDetailsTestOnly(fake_add_egress_response_));
  }

  void CheckPublicMetadataParams(
      const AddEgressRequest::PpnDataplaneRequestParams& params) {
    auto expected = CreateGetInitialDataResponse();
    auto public_metadata = expected.public_metadata_info().public_metadata();

    EXPECT_THAT(params.service_type,
                testing::Eq(public_metadata.service_type()));
    EXPECT_THAT(
        params.signing_key_version,
        testing::Eq(expected.at_public_metadata_public_key().key_version()));
    EXPECT_THAT(params.country,
                testing::Eq(public_metadata.exit_location().country()));
    EXPECT_THAT(params.city_geo_id,
                testing::Eq(public_metadata.exit_location().city_geo_id()));
    EXPECT_THAT(params.expiration,
                testing::Eq(absl::FromUnixSeconds(
                    public_metadata.expiration().seconds())));
  }

  void ExpectSuccessfulDatapathInit() {
    EXPECT_CALL(timer_interface_, StartTimer(_, absl::Minutes(5)))
        .WillOnce(Return(absl::OkStatus()));

    EXPECT_CALL(notification_, ControlPlaneConnected());

    EXPECT_CALL(egress_manager_, GetEgressSessionDetails)
        .WillRepeatedly(Invoke([&]() { return fake_add_egress_response_; }));

    EXPECT_CALL(http_fetcher_, LookupDns).WillRepeatedly(Return("0.0.0.0"));

    EXPECT_CALL(*datapath_, Start(_, _))
        .WillOnce(DoAll(InvokeWithoutArgs(&done_, &absl::Notification::Notify),
                        Return(absl::OkStatus())));
  }

  void StartSessionAndConnectDatapathOnCellular() {
    ExpectSuccessfulProvision();
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
                                          mtu: 1395)pb")));

    NetworkInfo expected_network_info;
    expected_network_info.set_network_id(123);
    expected_network_info.set_network_type(NetworkType::CELLULAR);
    EXPECT_CALL(
        *datapath_,
        SwitchNetwork(123, _, NetworkInfoEquals(expected_network_info), _))
        .WillOnce(Return(absl::OkStatus()));

    NetworkInfo network_info;
    network_info.set_network_id(123);
    network_info.set_network_type(NetworkType::CELLULAR);
    EXPECT_OK(session_->SetNetwork(network_info));
    WaitForNotifications();
    EXPECT_CALL(notification_, DatapathConnected());

    session_->DatapathEstablished();
    EXPECT_THAT(session_->GetActiveNetworkInfoTestOnly(),
                NetworkInfoEquals(expected_network_info));
  }

  void BringDatapathToConnected() {
    ExpectSuccessfulProvision();
    ExpectSuccessfulDatapathInit();

    session_->Start();

    WaitInitial();
    EXPECT_THAT(session_->LatestStatusTestOnly(), IsOk());

    EXPECT_EQ(session_->GetStateTestOnly(), Session::State::kConnected);

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
                                          mtu: 1395)pb")));

    NetworkInfo expected_network_info;
    expected_network_info.set_network_type(NetworkType::CELLULAR);
    EXPECT_CALL(
        *datapath_,
        SwitchNetwork(123, _, NetworkInfoEquals(expected_network_info), _))
        .WillOnce(Return(absl::OkStatus()));

    NetworkInfo network_info;
    network_info.set_network_type(NetworkType::CELLULAR);
    EXPECT_OK(session_->SetNetwork(network_info));

    EXPECT_CALL(notification_, DatapathConnected());
    session_->DatapathEstablished();
  }

  KryptonConfig config_{ParseTextProtoOrDie(
      R"pb(zinc_url: "http://www.example.com/auth"
           brass_url: "http://www.example.com/addegress"
           service_type: "service_type"
           datapath_protocol: BRIDGE
           copper_hostname_suffix: [ 'g-tun.com' ]
           enable_blind_signing: false
           dynamic_mtu_enabled: true
           public_metadata_enabled: true)pb")};

  MockSessionNotification notification_;
  MockHttpFetcher http_fetcher_;
  MockOAuth oauth_;
  utils::LooperThread notification_thread_{"Session Test"};
  MockAuth auth_{config_, &http_fetcher_, &oauth_, &notification_thread_};
  MockEgressManager egress_manager_{config_, &http_fetcher_,
                                    &notification_thread_};

  MockDatapath* datapath_;
  MockTimerInterface timer_interface_;
  TimerManager timer_manager_{&timer_interface_};

  MockVpnService vpn_service_;
  MockTunnelManager tunnel_manager_;
  std::unique_ptr<Session> session_;
  AddEgressResponse fake_add_egress_response_;
  DatapathInterface::NotificationInterface* datapath_notification_;
  bool is_rekey_ = false;
  absl::Notification done_;

  Auth::NotificationInterface* auth_notification_ = nullptr;
  EgressManager::NotificationInterface* egress_notification_ = nullptr;
};

// This test assumes Authentication was successful.

TEST_F(SessionTest, DatapathInitFailure) {
  absl::Notification done;
  ExpectSuccessfulProvision();

  EXPECT_CALL(egress_manager_, GetEgressSessionDetails)
      .WillRepeatedly(Invoke([&]() { return fake_add_egress_response_; }));

  EXPECT_CALL(http_fetcher_, LookupDns).WillRepeatedly(Return("0.0.0.0"));
  EXPECT_CALL(*datapath_, Start(_, _))
      .WillOnce(
          DoAll(InvokeWithoutArgs(&done, &absl::Notification::Notify),
                Return(absl::InvalidArgumentError("Initialization error"))));

  session_->Start();
  EXPECT_TRUE(done.WaitForNotificationWithTimeout(absl::Seconds(3)));
  EXPECT_THAT(session_->LatestStatusTestOnly(),
              StatusIs(util::error::INVALID_ARGUMENT, "Initialization error"));

  EXPECT_EQ(session_->GetStateTestOnly(), Session::State::kSessionError);
}

TEST_F(SessionTest, InitialDatapathEndpointChangeAndNoNetworkAvailable) {
  ExpectSuccessfulProvision();
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
                                        mtu: 1395)pb")));

  NetworkInfo expected_network_info;
  expected_network_info.set_network_type(NetworkType::CELLULAR);
  EXPECT_CALL(
      *datapath_,
      SwitchNetwork(123, _, NetworkInfoEquals(expected_network_info), _))
      .WillOnce(Return(absl::OkStatus()));

  NetworkInfo network_info;
  network_info.set_network_type(NetworkType::CELLULAR);

  EXPECT_OK(session_->SetNetwork(network_info));

  EXPECT_CALL(notification_, DatapathConnected());
  session_->DatapathEstablished();

  // No Network available.
  EXPECT_CALL(*datapath_, SwitchNetwork(123, _, Eq(std::nullopt), _))
      .WillOnce(Return(absl::OkStatus()));
  EXPECT_OK(session_->SetNetwork(std::nullopt));
}

TEST_F(SessionTest, SwitchNetworkToSameNetworkType) {
  StartSessionAndConnectDatapathOnCellular();

  // Switch network to same type.
  NetworkInfo new_network_info;
  new_network_info.set_network_type(NetworkType::CELLULAR);

  // Expect no tunnel fd change.
  EXPECT_CALL(*datapath_,
              SwitchNetwork(123, _, NetworkInfoEquals(new_network_info), _))
      .WillOnce(Return(absl::OkStatus()));

  EXPECT_OK(session_->SetNetwork(new_network_info));
  // Check all the parameters are correct in the session.
  EXPECT_THAT(session_->GetActiveNetworkInfoTestOnly(),
              NetworkInfoEquals(new_network_info));
}

TEST_F(SessionTest, DatapathReattemptFailure) {
  StartSessionAndConnectDatapathOnCellular();

  NetworkInfo expected_network_info;
  expected_network_info.set_network_id(123);
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
      EXPECT_CALL(*datapath_,
                  SwitchNetwork(
                      123,
                      Endpoint("[2604:ca00:f001:4::5]:2153",
                               "2604:ca00:f001:4::5", 2153, IPProtocol::kIPv6),
                      NetworkInfoEquals(expected_network_info), _))
          .WillOnce(Return(absl::OkStatus()));
    } else {
      EXPECT_CALL(*datapath_,
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

TEST_F(SessionTest, DatapathFailureAndSuccessfulBeforeReattempt) {
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

TEST_F(SessionTest, SwitchNetworkToDifferentNetworkType) {
  StartSessionAndConnectDatapathOnCellular();

  // Switch network to different type.
  NetworkInfo new_network_info;
  new_network_info.set_network_type(NetworkType::WIFI);

  EXPECT_CALL(*datapath_,
              SwitchNetwork(123, _, NetworkInfoEquals(new_network_info), _))
      .WillOnce(Return(absl::OkStatus()));

  EXPECT_OK(session_->SetNetwork(new_network_info));
  // Check all the parameters are correct in the session.
  EXPECT_THAT(session_->GetActiveNetworkInfoTestOnly(),
              NetworkInfoEquals(new_network_info));
}

TEST_F(SessionTest, TestEndpointChangeBeforeEstablishingSession) {
  absl::Notification done;
  // Switch network after auth is successful and before session is in
  // connected state.
  EXPECT_CALL(auth_, Start).WillOnce(Invoke([&]() {
    NetworkInfo network_info;
    network_info.set_network_type(NetworkType::CELLULAR);
    notification_thread_.Post([this, network_info]() {
      ASSERT_OK(session_->SetNetwork(network_info));
    });

    notification_thread_.Post([this]() {
      ASSERT_NE(auth_notification_, nullptr);
      auth_notification_->AuthSuccessful(false);
    });
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

  EXPECT_CALL(*datapath_, Start(_, _))
      .WillOnce(::testing::DoAll(
          InvokeWithoutArgs(&done, &absl::Notification::Notify),
          Return(absl::OkStatus())));

  NetworkInfo expected_network_info;
  expected_network_info.set_network_type(NetworkType::CELLULAR);
  EXPECT_CALL(
      *datapath_,
      SwitchNetwork(123, _, NetworkInfoEquals(expected_network_info), _))
      .WillOnce(Return(absl::OkStatus()));

  session_->Start();
  EXPECT_TRUE(done.WaitForNotificationWithTimeout(absl::Seconds(3)));
  EXPECT_CALL(notification_, DatapathConnected());
  session_->DatapathEstablished();
}

TEST_F(SessionTest, PopulatesDebugInfo) {
  session_->Start();

  DatapathDebugInfo datapath_debug_info;
  datapath_debug_info.set_uplink_packets_read(1);
  datapath_debug_info.set_downlink_packets_read(2);
  datapath_debug_info.set_decryption_errors(3);

  EXPECT_CALL(*datapath_, GetDebugInfo(_))
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

TEST_F(SessionTest, DatapathInitSuccessful) { BringDatapathToConnected(); }

TEST_F(SessionTest, DatapathPermanentFailure) {
  BringDatapathToConnected();

  EXPECT_CALL(notification_, DatapathDisconnected(_, _));
  session_->DatapathPermanentFailure(absl::InvalidArgumentError("some error"));
}

TEST_F(SessionTest, TestSetKeyMaterials) {
  ExpectSuccessfulProvision();
  ExpectSuccessfulDatapathInit();

  session_->Start();
  WaitInitial();

  is_rekey_ = true;
  absl::Notification rekey_done;
  ExpectSuccessfulProvision();
  EXPECT_CALL(*datapath_, SetKeyMaterials(_))
      .WillOnce(
          DoAll(InvokeWithoutArgs(&rekey_done, &absl::Notification::Notify),
                Return(absl::OkStatus())));
  SessionDebugInfo debug_info;
  session_->GetDebugInfo(&debug_info);
  EXPECT_EQ(debug_info.successful_rekeys(), 0);
  session_->DoRekey();
  EXPECT_TRUE(rekey_done.WaitForNotificationWithTimeout(absl::Seconds(3)));
  session_->GetDebugInfo(&debug_info);
  EXPECT_EQ(debug_info.successful_rekeys(), 1);
}

TEST_F(SessionTest, UplinkMtuUpdateHandler) {
  BringDatapathToConnected();

  EXPECT_CALL(*datapath_, PrepareForTunnelSwitch()).Times(1);
  EXPECT_CALL(tunnel_manager_, EnsureTunnelIsUp(_)).Times(1);
  EXPECT_CALL(*datapath_, SwitchTunnel()).Times(1);

  session_->DoUplinkMtuUpdate(123, 456);

  EXPECT_EQ(session_->GetUplinkMtuTestOnly(), 123);
  EXPECT_EQ(session_->GetTunnelMtuTestOnly(), 456);
}

TEST_F(SessionTest, UplinkMtuUpdateHandlerErrorWithNoExistingTunnel) {
  EXPECT_CALL(tunnel_manager_, EnsureTunnelIsUp(_)).Times(0);
  EXPECT_CALL(*datapath_, SwitchTunnel()).Times(0);
  EXPECT_CALL(*datapath_, Stop()).Times(1);
  EXPECT_CALL(notification_,
              ControlPlaneDisconnected(StatusIs(absl::StatusCode::kInternal)));

  session_->DoUplinkMtuUpdate(123, 456);
}

TEST_F(SessionTest, DownlinkMtuUpdateHandler) {
  session_->DoDownlinkMtuUpdate(123);
  EXPECT_EQ(session_->GetDownlinkMtuTestOnly(), 123);
}

TEST_F(SessionTest, UplinkMtuUpdateHandlerHttpStatusOk) {
  BringDatapathToConnected();

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
                                        mtu: 456)pb")));

  EXPECT_CALL(notification_, ControlPlaneDisconnected(_)).Times(0);

  session_->DoUplinkMtuUpdate(123, 456);

  EXPECT_EQ(session_->GetUplinkMtuTestOnly(), 123);
  EXPECT_EQ(session_->GetTunnelMtuTestOnly(), 456);
}

TEST_F(SessionTest, DownlinkMtuUpdateHandlerHttpStatusOk) {
  BringDatapathToConnected();

  absl::Notification mtu_update_done;
  std::string json_body;
  EXPECT_CALL(http_fetcher_, PostJson(_))
      .WillOnce([&mtu_update_done, &json_body](const HttpRequest& request) {
        absl::Cleanup cleanup = [&mtu_update_done] {
          mtu_update_done.Notify();
        };
        json_body = request.json_body();
        HttpResponse http_response;
        auto* http_status = http_response.mutable_status();
        http_status->set_code(200);
        return http_response;
      });

  EXPECT_CALL(notification_, ControlPlaneDisconnected(_)).Times(0);

  session_->DoDownlinkMtuUpdate(123);

  ASSERT_TRUE(mtu_update_done.WaitForNotificationWithTimeout(absl::Seconds(3)));

  EXPECT_EQ(session_->GetDownlinkMtuTestOnly(), 123);
  ASSERT_OK_AND_ASSIGN(auto json_obj, utils::StringToJson(json_body));
  ASSERT_TRUE(json_obj.contains(JsonKeys::kUplinkMtu));
  ASSERT_TRUE(json_obj.contains(JsonKeys::kDownlinkMtu));
  EXPECT_EQ(json_obj[JsonKeys::kUplinkMtu], 0);
  EXPECT_EQ(json_obj[JsonKeys::kDownlinkMtu], 123);
}

TEST_F(SessionTest, DownlinkMtuUpdateHandlerHttpStatusBadRequest) {
  BringDatapathToConnected();

  EXPECT_CALL(http_fetcher_, PostJson(_))
      .WillOnce([](const HttpRequest& /*request*/) {
        HttpResponse http_response;
        auto* http_status = http_response.mutable_status();
        http_status->set_code(400);
        http_status->set_message("Bad Request");
        return http_response;
      });

  absl::Notification notification_done;
  EXPECT_CALL(notification_, ControlPlaneDisconnected(
                                 StatusIs(absl::StatusCode::kInvalidArgument,
                                          HasSubstr("Bad Request"))))
      .WillOnce([&notification_done] { notification_done.Notify(); });

  session_->DoDownlinkMtuUpdate(123);

  ASSERT_TRUE(
      notification_done.WaitForNotificationWithTimeout(absl::Seconds(3)));
}

TEST(UpdatePathInfoTest, UpdatePathInfoRequestToJsonDefaultValues) {
  ppn::UpdatePathInfoRequest update_path_info;
  auto json_str = ProtoToJsonString(update_path_info);
  std::string expected = R"string(
  {
    "apn_type":"",
    "control_plane_sock_addr":"",
    "downlink_mtu":0,
    "mtu_update_signature":"",
    "session_id":0,
    "uplink_mtu":0,
    "verification_key":""
  })string";
  absl::StrReplaceAll({{"\n", ""}, {" ", ""}}, &expected);
  EXPECT_EQ(json_str, expected);
}

TEST(UpdatePathInfoTest, UpdatePathInfoRequestToJsonNonDefaultValues) {
  ppn::UpdatePathInfoRequest update_path_info;
  update_path_info.set_session_id(1);
  update_path_info.set_uplink_mtu(2);
  update_path_info.set_downlink_mtu(3);
  update_path_info.set_verification_key("foo");
  update_path_info.set_mtu_update_signature("bar");
  update_path_info.set_control_plane_sock_addr("192.168.1.1:1234");
  update_path_info.set_apn_type("ppn");
  auto json_str = ProtoToJsonString(update_path_info);
  std::string expected = R"string(
  {
    "apn_type":"ppn",
    "control_plane_sock_addr":"192.168.1.1:1234",
    "downlink_mtu":3,
    "mtu_update_signature":"YmFy",
    "session_id":1,
    "uplink_mtu":2,
    "verification_key":"Zm9v"
  })string";
  absl::StrReplaceAll({{"\n", ""}, {" ", ""}}, &expected);
  EXPECT_EQ(json_str, expected);
}
}  // namespace
}  // namespace krypton
}  // namespace privacy
