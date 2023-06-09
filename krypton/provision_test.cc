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

#include "privacy/net/krypton/provision.h"

#include <memory>
#include <string>
#include <utility>

#include "net/proto2/contrib/parse_proto/parse_text_proto.h"
#include "privacy/net/attestation/proto/attestation.proto.h"
#include "privacy/net/common/proto/auth_and_sign.proto.h"
#include "privacy/net/common/proto/get_initial_data.proto.h"
#include "privacy/net/krypton/add_egress_response.h"
#include "privacy/net/krypton/egress_manager.h"
#include "privacy/net/krypton/pal/mock_http_fetcher_interface.h"
#include "privacy/net/krypton/pal/mock_oauth_interface.h"
#include "privacy/net/krypton/proto/debug_info.proto.h"
#include "privacy/net/krypton/proto/http_fetcher.proto.h"
#include "privacy/net/krypton/proto/krypton_config.proto.h"
#include "privacy/net/krypton/utils/looper.h"
#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/absl/synchronization/notification.h"
#include "third_party/absl/time/time.h"
#include "third_party/anonymous_tokens/cpp/testing/utils.h"

namespace privacy {
namespace krypton {
namespace {

using ::proto2::contrib::parse_proto::ParseTextProtoOrDie;
using ::testing::_;
using ::testing::EqualsProto;
using ::testing::Return;
using ::testing::StrEq;
using ::testing::status::StatusIs;

MATCHER_P(RequestUrlMatcher, url, "") { return arg.url() == url; }

class MockNotification : public Provision::NotificationInterface {
 public:
  MOCK_METHOD(void, Provisioned, (const AddEgressResponse&, bool), (override));
  MOCK_METHOD(void, ProvisioningFailure, (absl::Status, bool), (override));
};

class ProvisionTest : public ::testing::Test {
 public:
  void SetUp() override {
    auto auth =
        std::make_unique<Auth>(config_, &http_fetcher_, &oauth_, &looper_);
    auto egress_manager =
        std::make_unique<EgressManager>(config_, &http_fetcher_, &looper_);
    provision_ = std::make_unique<Provision>(
        config_, std::move(auth), std::move(egress_manager), &http_fetcher_,
        &notification_, &looper_);

    ASSERT_OK_AND_ASSIGN(
        key_pair_, ::private_membership::anonymous_tokens::CreateTestKey());
    key_pair_.second.set_key_version(1);
    key_pair_.second.set_use_case("TEST_USE_CASE");

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

  void TearDown() override { provision_->Stop(); }

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

  KryptonConfig config_{ParseTextProtoOrDie(
      R"pb(zinc_url: "auth"
           brass_url: "add_egress"
           initial_data_url: "initial_data"
           service_type: "service_type"
           datapath_protocol: BRIDGE
           copper_hostname_suffix: [ 'g-tun.com' ]
           ip_geo_level: CITY
           enable_blind_signing: true
           dynamic_mtu_enabled: true
           public_metadata_enabled: true)pb")};

  utils::LooperThread looper_{"ProvisionTest Looper"};
  std::unique_ptr<Provision> provision_;

  MockHttpFetcher http_fetcher_;
  MockNotification notification_;
  MockOAuth oauth_;

  AddEgressResponse default_add_egress_response_;
  std::pair<bssl::UniquePtr<RSA>,
            ::private_membership::anonymous_tokens::RSABlindSignaturePublicKey>
      key_pair_;
};

TEST_F(ProvisionTest, AuthenticationFailure) {
  // Return a 500, which translates to a kInternalError
  EXPECT_CALL(http_fetcher_, PostJson(RequestUrlMatcher("initial_data")))
      .WillOnce([] {
        HttpResponse response;
        response.mutable_status()->set_code(500);
        return response;
      });

  absl::Notification done;
  EXPECT_CALL(notification_,
              ProvisioningFailure(StatusIs(absl::StatusCode::kInternal), false))
      .WillOnce([&done] { done.Notify(); });

  provision_->Start();
  EXPECT_TRUE(done.WaitForNotificationWithTimeout(absl::Seconds(1)));
}

TEST_F(ProvisionTest, AuthenticationFailurePermanent) {
  // Return a 403, which translates to a kPermissionDenied which is permanent
  EXPECT_CALL(http_fetcher_, PostJson(RequestUrlMatcher("initial_data")))
      .WillOnce([] {
        HttpResponse response;
        response.mutable_status()->set_code(403);
        return response;
      });

  absl::Notification done;
  EXPECT_CALL(
      notification_,
      ProvisioningFailure(StatusIs(absl::StatusCode::kPermissionDenied), true))
      .WillOnce([&done] { done.Notify(); });

  provision_->Start();
  EXPECT_TRUE(done.WaitForNotificationWithTimeout(absl::Seconds(1)));
}

TEST_F(ProvisionTest, EgressUnavailable) {
  EXPECT_CALL(http_fetcher_, PostJson(RequestUrlMatcher("initial_data")));
  EXPECT_CALL(http_fetcher_, PostJson(RequestUrlMatcher("auth")));
  EXPECT_CALL(http_fetcher_, PostJson(RequestUrlMatcher("add_egress")))
      .WillOnce([] {
        HttpResponse response;
        response.mutable_status()->set_code(500);
        return response;
      });

  absl::Notification done;
  EXPECT_CALL(notification_,
              ProvisioningFailure(StatusIs(absl::StatusCode::kInternal), false))
      .WillOnce([&done] { done.Notify(); });

  provision_->Start();
  EXPECT_TRUE(done.WaitForNotificationWithTimeout(absl::Seconds(1)));
}

TEST_F(ProvisionTest, EgressAvailable) {
  absl::Notification done;
  AddEgressResponse provisioned_response;
  EXPECT_CALL(notification_, Provisioned(_, /*is_rekey=*/false))
      .WillOnce([&done, &provisioned_response](AddEgressResponse response,
                                               bool /*is_rekey*/) {
        provisioned_response = response;
        done.Notify();
      });

  provision_->Start();
  ASSERT_TRUE(done.WaitForNotificationWithTimeout(absl::Seconds(1)));

  ASSERT_OK_AND_ASSIGN(auto actual_ppn_dataplane_response,
                       provisioned_response.ppn_dataplane_response());
  ASSERT_OK_AND_ASSIGN(
      auto expected_add_egress_response,
      AddEgressResponse::FromProto(CreateAddEgressHttpResponse()));
  ASSERT_OK_AND_ASSIGN(auto expected_ppn_dataplane_response,
                       expected_add_egress_response.ppn_dataplane_response());
  EXPECT_THAT(actual_ppn_dataplane_response,
              EqualsProto(expected_ppn_dataplane_response));
}

TEST_F(ProvisionTest, Rekey) {
  absl::Notification provisioning_done;
  absl::Notification rekey_done;
  auto fake_rekey_response = CreateRekeyResponse();

  EXPECT_CALL(notification_, Provisioned(_, _))
      .WillOnce([&provisioning_done]() { provisioning_done.Notify(); });

  provision_->Start();

  ASSERT_TRUE(
      provisioning_done.WaitForNotificationWithTimeout(absl::Seconds(1)));

  ASSERT_OK_AND_ASSIGN(auto original_transform_params,
                       provision_->GetTransformParams());
  auto original_ipsec_params = original_transform_params.bridge();

  EXPECT_CALL(http_fetcher_, PostJson(RequestUrlMatcher("initial_data")));
  EXPECT_CALL(http_fetcher_, PostJson(RequestUrlMatcher("auth")));
  EXPECT_CALL(http_fetcher_, PostJson(RequestUrlMatcher("add_egress")))
      .WillOnce(Return(fake_rekey_response));

  AddEgressResponse provisioned_response;
  EXPECT_CALL(notification_, Provisioned(_, /*is_rekey=*/true))
      .WillOnce([&rekey_done, &provisioned_response](AddEgressResponse response,
                                                     bool /*is_rekey*/) {
        provisioned_response = response;
        rekey_done.Notify();
      });

  provision_->Rekey();

  ASSERT_TRUE(rekey_done.WaitForNotificationWithTimeout(absl::Seconds(1)));

  ASSERT_OK_AND_ASSIGN(auto actual_ppn_dataplane_response,
                       provisioned_response.ppn_dataplane_response());
  ASSERT_OK_AND_ASSIGN(auto expected_rekey_response,
                       AddEgressResponse::FromProto(fake_rekey_response));
  ASSERT_OK_AND_ASSIGN(auto expected_ppn_dataplane_response,
                       expected_rekey_response.ppn_dataplane_response());
  EXPECT_THAT(actual_ppn_dataplane_response,
              EqualsProto(expected_ppn_dataplane_response));

  ASSERT_OK_AND_ASSIGN(auto rekeyed_transform_params,
                       provision_->GetTransformParams());
  auto rekeyed_ipsec_params = rekeyed_transform_params.bridge();

  EXPECT_NE(rekeyed_ipsec_params.uplink_key(),
            original_ipsec_params.uplink_key());
  EXPECT_NE(rekeyed_ipsec_params.downlink_key(),
            original_ipsec_params.downlink_key());
  EXPECT_EQ(rekeyed_ipsec_params.session_id(),
            original_ipsec_params.session_id());
  EXPECT_EQ(rekeyed_ipsec_params.cipher_suite_key_length(),
            original_ipsec_params.cipher_suite_key_length());
}

TEST_F(ProvisionTest, TestAuthResponseSetCopperControllerHostname) {
  absl::Notification done;

  EXPECT_CALL(http_fetcher_, PostJson(RequestUrlMatcher("initial_data")));
  EXPECT_CALL(http_fetcher_, PostJson(RequestUrlMatcher("auth")))
      .WillOnce([this](HttpRequest request) {
        return CreateAuthHttpResponse(request, "eu.b.g-tun.com");
      });
  EXPECT_CALL(http_fetcher_, PostJson(RequestUrlMatcher("add_egress")));

  EXPECT_CALL(http_fetcher_, LookupDns(StrEq("eu.b.g-tun.com")));

  EXPECT_CALL(notification_, Provisioned(_, _)).WillOnce([&done]() {
    done.Notify();
  });

  provision_->Start();
  EXPECT_TRUE(done.WaitForNotificationWithTimeout(absl::Seconds(1)));
}

TEST_F(ProvisionTest, TestAuthResponseDefaultCopperControllerHostname) {
  absl::Notification done;

  EXPECT_CALL(http_fetcher_, LookupDns(StrEq("na.b.g-tun.com")));

  EXPECT_CALL(notification_, Provisioned(_, _)).WillOnce([&done]() {
    done.Notify();
  });

  provision_->Start();
  EXPECT_TRUE(done.WaitForNotificationWithTimeout(absl::Seconds(1)));
}

TEST_F(ProvisionTest, RekeyBeforeStartFails) {
  absl::Notification failed;

  EXPECT_CALL(notification_,
              ProvisioningFailure(
                  StatusIs(absl::StatusCode::kFailedPrecondition), false))
      .WillOnce([&failed] { failed.Notify(); });

  provision_->Rekey();

  EXPECT_TRUE(failed.WaitForNotificationWithTimeout(absl::Seconds(3)));
}

TEST_F(ProvisionTest, GenerateSignatureBeforeStartFails) {
  std::string data = "test";
  EXPECT_THAT(provision_->GenerateSignature(data),
              StatusIs(absl::StatusCode::kFailedPrecondition));
}

TEST_F(ProvisionTest, GetTransformParamsBeforeStartFails) {
  EXPECT_THAT(provision_->GetTransformParams(),
              StatusIs(absl::StatusCode::kFailedPrecondition));
}

TEST_F(ProvisionTest, GetDebugInfo) {
  KryptonDebugInfo debug_info;
  EXPECT_FALSE(debug_info.has_auth());
  EXPECT_FALSE(debug_info.has_egress());
  provision_->GetDebugInfo(&debug_info);
  EXPECT_TRUE(debug_info.has_auth());
  EXPECT_TRUE(debug_info.has_egress());
}

TEST_F(ProvisionTest, CollectTelemetry) {
  absl::Notification done;
  EXPECT_CALL(notification_, Provisioned(_, _)).WillOnce([&done] {
    done.Notify();
  });

  provision_->Start();
  ASSERT_TRUE(done.WaitForNotificationWithTimeout(absl::Seconds(1)));

  KryptonTelemetry telemetry;
  provision_->CollectTelemetry(&telemetry);
  EXPECT_NE(telemetry.auth_latency_size(), 0);
  EXPECT_NE(telemetry.egress_latency_size(), 0);
}

}  // namespace
}  // namespace krypton
}  // namespace privacy
