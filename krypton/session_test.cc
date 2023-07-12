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
#include "privacy/net/attestation/proto/attestation.proto.h"
#include "privacy/net/common/proto/auth_and_sign.proto.h"
#include "privacy/net/common/proto/get_initial_data.proto.h"
#include "privacy/net/common/proto/public_metadata.proto.h"
#include "privacy/net/common/proto/update_path_info.proto.h"
#include "privacy/net/krypton/add_egress_request.h"
#include "privacy/net/krypton/add_egress_response.h"
#include "privacy/net/krypton/auth.h"
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
#include "privacy/net/krypton/proto/krypton_telemetry.proto.h"
#include "privacy/net/krypton/proto/network_info.proto.h"
#include "privacy/net/krypton/proto/network_type.proto.h"
#include "privacy/net/krypton/proto/tun_fd_data.proto.h"
#include "privacy/net/krypton/timer_manager.h"
#include "privacy/net/krypton/tunnel_manager.h"
#include "privacy/net/krypton/utils/json_util.h"
#include "privacy/net/krypton/utils/looper.h"
#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"
#include "third_party/absl/cleanup/cleanup.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/strings/escaping.h"
#include "third_party/absl/strings/str_replace.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/absl/synchronization/mutex.h"
#include "third_party/absl/synchronization/notification.h"
#include "third_party/absl/time/time.h"
#include "third_party/absl/types/optional.h"
#include "third_party/anonymous_tokens/cpp/testing/proto_utils.h"
#include "third_party/anonymous_tokens/cpp/testing/utils.h"
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

MATCHER_P(RequestUrlMatcher, url, "") { return arg.url() == url; }

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

// Tests Bridge dataplane and PPN control plane.
class SessionTest : public ::testing::Test {
 public:
  SessionTest() : tunnel_manager_(&vpn_service_, false) {}

  void SetUp() override {
    auto datapath = std::make_unique<MockDatapath>();
    datapath_ = datapath.get();

    EXPECT_CALL(*datapath_, RegisterNotificationHandler)
        .WillOnce(
            Invoke([&](DatapathInterface::NotificationInterface* notification) {
              datapath_notification_ = notification;
            }));

    auto auth = std::make_unique<Auth>(config_, &http_fetcher_, &oauth_);
    auto egress_manager =
        std::make_unique<EgressManager>(config_, &http_fetcher_);
    session_ = std::make_unique<Session>(
        config_, std::move(auth), std::move(egress_manager),
        std::move(datapath), &vpn_service_, &timer_manager_, &http_fetcher_,
        &tunnel_manager_, std::nullopt, &looper_);
    session_->RegisterNotificationHandler(&notification_);

    ASSERT_OK_AND_ASSIGN(
        key_pair_, ::private_membership::anonymous_tokens::CreateTestKey());
    key_pair_.second.set_key_version(1);
    key_pair_.second.set_use_case("TEST_USE_CASE");

    // Configure default behavior to be successful auth and egress
    ppn::AttestationData attestation_data;
    ON_CALL(oauth_, GetAttestationData(_))
        .WillByDefault(Return(attestation_data));
    ON_CALL(oauth_, GetOAuthToken).WillByDefault(Return("some_token"));

    ON_CALL(http_fetcher_, LookupDns(_)).WillByDefault(Return("0.0.0.0"));
    ON_CALL(http_fetcher_, PostJson(RequestUrlMatcher("initial_data")))
        .WillByDefault([this] { return CreateInitialDataHttpResponse(); });
    ON_CALL(http_fetcher_, PostJson(RequestUrlMatcher("auth")))
        .WillByDefault([this](const HttpRequest& http_request) {
          return CreateAuthHttpResponse(http_request);
        });
    ON_CALL(http_fetcher_, PostJson(RequestUrlMatcher("add_egress")))
        .WillByDefault([this] { return CreateAddEgressHttpResponse(); });
  }

  HttpResponse CreateAddEgressHttpResponse() {
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
    return fake_add_egress_http_response;
  }

  HttpResponse CreateRekeyResponse() {
    // Return a response with different uplink_spi, server_nonce, and
    // egress_point_public_value
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
        "egress_point_public_value": "a22j+91TxHtS5qa625KCE5ybsyzPR1wkTDWHV2qSQQc=",
        "server_nonce": "Uzt2lEzyvBYzjLAP3E+dAA==",
        "uplink_spi": 456,
        "expiry": "2020-08-07T01:06:13+00:00"
      }
    })string");
    return fake_add_egress_http_response;
  }

  HttpResponse CreateAuthHttpResponse(
      HttpRequest auth_and_sign_request,
      absl::string_view copper_controller_hostname = "") {
    privacy::ppn::AuthAndSignRequest request;
    EXPECT_TRUE(request.ParseFromString(auth_and_sign_request.proto_body()));

    // Construct AuthAndSignResponse.
    ppn::AuthAndSignResponse auth_response;
    for (const auto& request_token : request.blinded_token()) {
      std::string decoded_blinded_token;
      EXPECT_TRUE(absl::Base64Unescape(request_token, &decoded_blinded_token));
      absl::StatusOr<std::string> serialized_token =
          // TODO This is for RSA signatures which don't take
          // public metadata into account. Eventually this will need to be
          // updated.
          private_membership::anonymous_tokens::TestSign(decoded_blinded_token,
                                                         key_pair_.first.get());
      EXPECT_OK(serialized_token);
      auth_response.add_blinded_token_signature(
          absl::Base64Escape(*serialized_token));
    }

    auth_response.set_copper_controller_hostname(copper_controller_hostname);

    // add to http response
    privacy::krypton::HttpResponse response;
    response.mutable_status()->set_code(200);
    response.mutable_status()->set_message("OK");
    response.set_proto_body(auth_response.SerializeAsString());
    return response;
  }

  void TearDown() override {
    session_->Stop(/*forceFailOpen=*/true);
    tunnel_manager_.Stop();
  }

  ppn::GetInitialDataResponse CreateGetInitialDataResponse() {
    ppn::GetInitialDataResponse response = ParseTextProtoOrDie(R"pb(
      at_public_metadata_public_key: {
        use_case: "TEST_USE_CASE",
        key_version: 2,
        serialized_public_key: "",
        expiration_time: { seconds: 0, nanos: 0 },
        key_validity_start_time: { seconds: 0, nanos: 0 },
        sig_hash_type: AT_HASH_TYPE_SHA256,
        mask_gen_function: AT_MGF_SHA256,
        salt_length: 2,
        key_size: 256,
        message_mask_type: AT_MESSAGE_MASK_CONCAT,
        message_mask_size: 2
      },
      public_metadata_info: {
        public_metadata: {
          exit_location: { country: "US", city_geo_id: "us_ca_san_diego" },
          service_type: "service_type",
          expiration: { seconds: 900, nanos: 0 },
          debug_mode: 0,
        },
        validation_version: 1
      }
    )pb");

    *response.mutable_at_public_metadata_public_key() = key_pair_.second;

    return response;
  }

  HttpResponse CreateInitialDataHttpResponse() {
    HttpResponse fake_initial_data_http_response;
    fake_initial_data_http_response.mutable_status()->set_code(200);
    fake_initial_data_http_response.mutable_status()->set_message("OK");
    fake_initial_data_http_response.set_proto_body(
        CreateGetInitialDataResponse().SerializeAsString());
    return fake_initial_data_http_response;
  }

  TunFdData GetTunFdData(int mtu = 1395) {
    TunFdData tun_fd_data =
        ParseTextProtoOrDie(R"pb(tunnel_ip_addresses {
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
                                 is_metered: false)pb");
    tun_fd_data.set_mtu(mtu);
    return tun_fd_data;
  }

  void WaitForDatapathStart() {
    ASSERT_TRUE(
        datapath_started_.WaitForNotificationWithTimeout(absl::Seconds(3)));
  }

  void WaitForNotifications() {
    absl::Mutex lock;
    absl::CondVar condition;
    absl::MutexLock l(&lock);
    looper_.Post([&lock, &condition] {
      absl::MutexLock l(&lock);
      condition.SignalAll();
    });
    condition.Wait(&lock);
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

    EXPECT_CALL(*datapath_, Start(_, _))
        .WillOnce(DoAll(
            InvokeWithoutArgs(&datapath_started_, &absl::Notification::Notify),
            Return(absl::OkStatus())));
  }

  void BringDatapathToConnected() {
    ExpectSuccessfulDatapathInit();

    session_->Start();

    WaitForDatapathStart();
    EXPECT_THAT(session_->LatestStatusTestOnly(), IsOk());

    EXPECT_EQ(session_->GetStateTestOnly(), Session::State::kConnected);

    EXPECT_CALL(vpn_service_, CreateTunnel(EqualsProto(GetTunFdData())));

    NetworkInfo network_info;
    network_info.set_network_id(123);
    network_info.set_network_type(NetworkType::CELLULAR);
    EXPECT_CALL(*datapath_,
                SwitchNetwork(123, _, NetworkInfoEquals(network_info), _))
        .WillOnce(Return(absl::OkStatus()));

    EXPECT_OK(session_->SetNetwork(network_info));

    EXPECT_CALL(notification_, DatapathConnected());
    session_->DatapathEstablished();
  }

  KryptonConfig config_{ParseTextProtoOrDie(
      R"pb(zinc_url: "auth"
           brass_url: "add_egress"
           initial_data_url: "initial_data"
           update_path_info_url: "update_path_info"
           service_type: "service_type"
           datapath_protocol: BRIDGE
           copper_hostname_suffix: [ 'g-tun.com' ]
           ip_geo_level: CITY
           enable_blind_signing: true
           dynamic_mtu_enabled: true
           public_metadata_enabled: true)pb")};

  MockSessionNotification notification_;
  MockHttpFetcher http_fetcher_;
  MockOAuth oauth_;
  utils::LooperThread looper_{"SessionTest Looper"};

  MockDatapath* datapath_;
  MockTimerInterface timer_interface_;
  TimerManager timer_manager_{&timer_interface_};

  MockVpnService vpn_service_;
  TunnelManager tunnel_manager_;
  std::unique_ptr<Session> session_;
  DatapathInterface::NotificationInterface* datapath_notification_;
  absl::Notification datapath_started_;

  Auth::NotificationInterface* auth_notification_ = nullptr;
  EgressManager::NotificationInterface* egress_notification_ = nullptr;

  std::pair<bssl::UniquePtr<RSA>,
            ::private_membership::anonymous_tokens::RSABlindSignaturePublicKey>
      key_pair_;
};

TEST_F(SessionTest, DatapathInitFailure) {
  absl::Notification done;

  EXPECT_CALL(*datapath_, Start(_, _)).WillOnce([&done] {
    absl::Cleanup cleanup = [&done] { done.Notify(); };
    return absl::InvalidArgumentError("Initialization error");
  });

  session_->Start();
  EXPECT_TRUE(done.WaitForNotificationWithTimeout(absl::Seconds(3)));
  EXPECT_THAT(session_->LatestStatusTestOnly(),
              StatusIs(util::error::INVALID_ARGUMENT, "Initialization error"));

  EXPECT_EQ(session_->GetStateTestOnly(), Session::State::kSessionError);
}

TEST_F(SessionTest, DatapathInitSuccessful) { BringDatapathToConnected(); }

TEST_F(SessionTest, InitialDatapathEndpointChangeAndNoNetworkAvailable) {
  ExpectSuccessfulDatapathInit();

  session_->Start();

  WaitForDatapathStart();
  EXPECT_CALL(vpn_service_, CreateTunnel(EqualsProto(GetTunFdData())));

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
  BringDatapathToConnected();

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
  BringDatapathToConnected();

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
  BringDatapathToConnected();

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
  BringDatapathToConnected();

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
  EXPECT_CALL(*datapath_, SwitchNetwork(_, _, _, _)).Times(0);

  NetworkInfo network_info;
  network_info.set_network_id(123);
  network_info.set_network_type(NetworkType::CELLULAR);
  ASSERT_OK(session_->SetNetwork(network_info));

  ExpectSuccessfulDatapathInit();

  EXPECT_CALL(*datapath_,
              SwitchNetwork(_, _, NetworkInfoEquals(network_info), _));

  session_->Start();

  WaitForDatapathStart();

  absl::Notification datapath_connected;
  EXPECT_CALL(notification_, DatapathConnected())
      .WillOnce([&datapath_connected] { datapath_connected.Notify(); });
  session_->DatapathEstablished();

  EXPECT_TRUE(
      datapath_connected.WaitForNotificationWithTimeout(absl::Seconds(1)));
}

TEST_F(SessionTest, PopulatesDebugInfo) {
  NetworkInfo network_info;
  network_info.set_network_type(NetworkType::CELLULAR);
  network_info.set_network_id(123);
  ASSERT_OK(session_->SetNetwork(network_info));

  DatapathDebugInfo datapath_debug_info;
  datapath_debug_info.set_uplink_packets_read(1);
  datapath_debug_info.set_downlink_packets_read(2);
  datapath_debug_info.set_decryption_errors(3);

  EXPECT_CALL(*datapath_, GetDebugInfo(_))
      .WillRepeatedly(SetArgPointee<0>(datapath_debug_info));

  KryptonDebugInfo debug_info;
  session_->GetDebugInfo(&debug_info);

  EXPECT_THAT(*debug_info.mutable_session(), EqualsProto(R"pb(
    state: "kInitialized"
    status: "OK"
    active_network < network_type: CELLULAR network_id: 123 >
    successful_rekeys: 0
    network_switches: 1
    datapath: <
      uplink_packets_read: 1
      downlink_packets_read: 2
      decryption_errors: 3
    >
  )pb"));

  EXPECT_TRUE(debug_info.has_auth());
  EXPECT_TRUE(debug_info.has_egress());
}

TEST_F(SessionTest, CollectTelemetry) {
  BringDatapathToConnected();

  KryptonTelemetry telemetry;
  session_->CollectTelemetry(&telemetry);

  EXPECT_EQ(telemetry.network_switches(), 2);
  EXPECT_EQ(telemetry.successful_rekeys(), 0);
  EXPECT_EQ(telemetry.auth_latency_size(), 1);
  EXPECT_EQ(telemetry.egress_latency_size(), 1);
}

TEST_F(SessionTest, DatapathPermanentFailure) {
  BringDatapathToConnected();

  EXPECT_CALL(notification_, DatapathDisconnected(_, _));
  session_->DatapathPermanentFailure(absl::InvalidArgumentError("some error"));
}

TEST_F(SessionTest, TestSetKeyMaterials) {
  ExpectSuccessfulDatapathInit();

  session_->Start();
  WaitForDatapathStart();

  absl::Notification rekey_done;
  EXPECT_CALL(*datapath_, SetKeyMaterials(_)).WillOnce([&rekey_done] {
    absl::Cleanup cleanup = [&rekey_done] { rekey_done.Notify(); };
    return absl::OkStatus();
  });
  KryptonDebugInfo debug_info;
  session_->GetDebugInfo(&debug_info);
  EXPECT_EQ(debug_info.mutable_session()->successful_rekeys(), 0);
  session_->DoRekey();
  EXPECT_TRUE(rekey_done.WaitForNotificationWithTimeout(absl::Seconds(3)));
  session_->GetDebugInfo(&debug_info);
  EXPECT_EQ(debug_info.mutable_session()->successful_rekeys(), 1);
}

TEST_F(SessionTest, UplinkMtuUpdateHandler) {
  BringDatapathToConnected();

  EXPECT_CALL(*datapath_, PrepareForTunnelSwitch());
  EXPECT_CALL(vpn_service_, CreateTunnel(_));
  EXPECT_CALL(*datapath_, SwitchTunnel());

  session_->DoUplinkMtuUpdate(/*uplink_mtu=*/123, /*tunnel_mtu=*/456);

  EXPECT_EQ(session_->GetUplinkMtuTestOnly(), 123);
  EXPECT_EQ(session_->GetTunnelMtuTestOnly(), 456);
}

TEST_F(SessionTest, UplinkMtuUpdateHandlerSessionDisconnected) {
  session_->DoUplinkMtuUpdate(/*uplink_mtu=*/123, /*tunnel_mtu=*/456);

  EXPECT_NE(session_->GetUplinkMtuTestOnly(), 123);
  EXPECT_NE(session_->GetTunnelMtuTestOnly(), 456);
}

TEST_F(SessionTest, DownlinkMtuUpdateHandler) {
  BringDatapathToConnected();

  session_->DoDownlinkMtuUpdate(/*downlink_mtu=*/123);
  EXPECT_EQ(session_->GetDownlinkMtuTestOnly(), 123);
}

TEST_F(SessionTest, DownlinkMtuUpdateHandlerSessionDisconnected) {
  session_->DoDownlinkMtuUpdate(/*downlink_mtu=*/123);
  EXPECT_NE(session_->GetDownlinkMtuTestOnly(), 123);
}

TEST_F(SessionTest, UplinkMtuUpdateHandlerHttpStatusOk) {
  BringDatapathToConnected();

  EXPECT_CALL(vpn_service_,
              CreateTunnel(EqualsProto(GetTunFdData(/*mtu=*/456))));

  EXPECT_CALL(notification_, ControlPlaneDisconnected(_)).Times(0);

  session_->DoUplinkMtuUpdate(/*uplink_mtu=*/123, /*tunnel_mtu=*/456);

  EXPECT_EQ(session_->GetUplinkMtuTestOnly(), 123);
  EXPECT_EQ(session_->GetTunnelMtuTestOnly(), 456);
}

TEST_F(SessionTest, DownlinkMtuUpdateHandlerHttpStatusOk) {
  BringDatapathToConnected();

  absl::Notification mtu_update_done;
  std::string json_body;
  EXPECT_CALL(http_fetcher_, PostJson(RequestUrlMatcher("update_path_info")))
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

  session_->DoDownlinkMtuUpdate(/*downlink_mtu=*/123);

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

  session_->DoDownlinkMtuUpdate(/*downlink_mtu=*/123);

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
