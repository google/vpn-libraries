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

#include "google/protobuf/timestamp.proto.h"
#include "net/proto2/contrib/parse_proto/parse_text_proto.h"
#include "privacy/net/common/proto/auth_and_sign.proto.h"
#include "privacy/net/common/proto/get_initial_data.proto.h"
#include "privacy/net/common/proto/public_metadata.proto.h"
#include "privacy/net/krypton/add_egress_request.h"
#include "privacy/net/krypton/add_egress_response.h"
#include "privacy/net/krypton/auth.h"
#include "privacy/net/krypton/auth_and_sign_response.h"
#include "privacy/net/krypton/egress_manager.h"
#include "privacy/net/krypton/pal/mock_http_fetcher_interface.h"
#include "privacy/net/krypton/pal/mock_oauth_interface.h"
#include "privacy/net/krypton/proto/http_fetcher.proto.h"
#include "privacy/net/krypton/proto/krypton_config.proto.h"
#include "privacy/net/krypton/utils/looper.h"
#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/synchronization/notification.h"
#include "third_party/absl/time/time.h"

namespace privacy {
namespace krypton {
namespace {

using ::proto2::contrib::parse_proto::ParseTextProtoOrDie;
using ::testing::_;
using ::testing::EqualsProto;
using ::testing::Return;
using ::testing::StrEq;
using ::testing::status::StatusIs;

MATCHER_P(PublicMetadataParamsEq, expected,
          "Check fields of PublicMetadata params") {
  ppn::PublicMetadata public_metadata =
      expected.public_metadata_info().public_metadata();
  ::google::protobuf::Timestamp expiration = public_metadata.expiration();

  bool match = true;
  match &= arg.service_type == public_metadata.service_type();
  match &= arg.signing_key_version ==
           expected.at_public_metadata_public_key().key_version();
  match &= arg.country == public_metadata.exit_location().country();
  match &= arg.city_geo_id == public_metadata.exit_location().city_geo_id();
  match &= arg.debug_mode == public_metadata.debug_mode();
  match &= arg.expiration == absl::FromUnixSeconds(expiration.seconds());
  return match;
}

// Mock the Auth.
class MockAuth : public Auth {
 public:
  using Auth::Auth;
  MOCK_METHOD(void, Start, (bool), (override));
  MOCK_METHOD(AuthAndSignResponse, auth_response, (), (const, override));
  MOCK_METHOD(ppn::GetInitialDataResponse, initial_data_response, (),
              (const, override));
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

class MockNotification : public Provision::NotificationInterface {
 public:
  MOCK_METHOD(void, Provisioned, (const AddEgressResponse&, bool), (override));
  MOCK_METHOD(void, ProvisioningFailure, (absl::Status, bool), (override));
};

class ProvisionTest : public ::testing::Test {
 public:
  void SetUp() override {
    provision_ = std::make_unique<Provision>(config_, &auth_, &egress_manager_,
                                             &http_fetcher_, &notification_,
                                             &notification_thread_);

    ON_CALL(http_fetcher_, LookupDns(_)).WillByDefault(Return("0.0.0.0"));

    // Configure the default auth behavior to succeed with the default response
    ON_CALL(auth_, initial_data_response)
        .WillByDefault(Return(CreateGetInitialDataResponse()));

    ON_CALL(auth_, Start(_)).WillByDefault([this](bool is_rekey) {
      notification_thread_.Post(
          [this, is_rekey] { provision_->AuthSuccessful(is_rekey); });
    });

    ASSERT_OK_AND_ASSIGN(auto default_auth_response,
                         CreateAuthAndSignResponse());
    ON_CALL(auth_, auth_response).WillByDefault([default_auth_response] {
      return default_auth_response;
    });

    // Configure default egress_manager_ behavior to successfully egress
    ON_CALL(egress_manager_, GetEgressNodeForPpnIpSec(PublicMetadataParamsEq(
                                 CreateGetInitialDataResponse())))
        .WillByDefault(
            [this](const AddEgressRequest::PpnDataplaneRequestParams& params) {
              EXPECT_EQ(params.dataplane_protocol, config_.datapath_protocol());
              EXPECT_TRUE(params.dynamic_mtu_enabled);
              notification_thread_.Post(
                  [this] { provision_->EgressAvailable(/*is_rekey=*/false); });
              return absl::OkStatus();
            });

    ASSERT_OK_AND_ASSIGN(default_add_egress_response_,
                         CreateAddEgressResponse());
    ON_CALL(egress_manager_, GetEgressSessionDetails)
        .WillByDefault(Return(default_add_egress_response_));
  }

  void TearDown() override {
    auth_.Stop();
    egress_manager_.Stop();
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
          debug_mode: 0,
        },
        validation_version: 1
      },
      attestation: { attestation_nonce: "some_nonce" }
    )pb");
    return response;
  }

  absl::StatusOr<AddEgressResponse> CreateAddEgressResponse() {
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

    return AddEgressResponse::FromProto(fake_add_egress_http_response);
  }

  absl::StatusOr<AddEgressResponse> CreateRekeyResponse() {
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

    return AddEgressResponse::FromProto(fake_add_egress_http_response);
  }

  absl::StatusOr<AuthAndSignResponse> CreateAuthAndSignResponse(
      const std::string& copper_controller_hostname = "") {
    ppn::AuthAndSignResponse auth_response_proto;
    auth_response_proto.set_copper_controller_hostname(
        copper_controller_hostname);

    // add to http response
    privacy::krypton::HttpResponse response;
    response.mutable_status()->set_code(200);
    response.mutable_status()->set_message("OK");
    response.set_proto_body(auth_response_proto.SerializeAsString());

    // Construct AuthAndSignResponse.
    AuthAndSignResponse auth_response;
    return AuthAndSignResponse::FromProto(response, config_,
                                          /*enforce_copper_suffix=*/true);
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

  utils::LooperThread notification_thread_{"Provision Test"};
  std::unique_ptr<Provision> provision_;

  MockHttpFetcher http_fetcher_;
  MockNotification notification_;
  MockOAuth oauth_;
  MockAuth auth_{config_, &http_fetcher_, &oauth_, &notification_thread_};
  MockEgressManager egress_manager_{config_, &http_fetcher_,
                                    &notification_thread_};

  AddEgressResponse default_add_egress_response_;
};

TEST_F(ProvisionTest, AuthenticationFailure) {
  EXPECT_CALL(auth_, Start).WillOnce([this] {
    notification_thread_.Post(
        [this] { provision_->AuthFailure(absl::InternalError("Some error")); });
  });

  absl::Notification done;
  EXPECT_CALL(notification_,
              ProvisioningFailure(StatusIs(absl::StatusCode::kInternal), false))
      .WillOnce([&done] { done.Notify(); });

  provision_->Start();
  EXPECT_TRUE(done.WaitForNotificationWithTimeout(absl::Seconds(1)));
}

TEST_F(ProvisionTest, AuthenticationFailurePermanent) {
  EXPECT_CALL(auth_, Start).WillOnce([this]() {
    notification_thread_.Post([this] {
      provision_->AuthFailure(absl::PermissionDeniedError("Some error"));
    });
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
  EXPECT_CALL(egress_manager_, GetEgressNodeForPpnIpSec(_)).WillOnce([this] {
    notification_thread_.Post([this] {
      provision_->EgressUnavailable(absl::InternalError("Some error"));
    });
    return absl::OkStatus();
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

  ASSERT_OK_AND_ASSIGN(auto ppn_dataplane_response,
                       provisioned_response.ppn_dataplane_response());
  ASSERT_OK_AND_ASSIGN(auto expected_response,
                       default_add_egress_response_.ppn_dataplane_response());
  EXPECT_THAT(ppn_dataplane_response, EqualsProto(expected_response));
}

TEST_F(ProvisionTest, Rekey) {
  absl::Notification provisioning_done;
  absl::Notification rekey_done;
  ASSERT_OK_AND_ASSIGN(auto fake_rekey_response, CreateRekeyResponse());

  EXPECT_CALL(notification_, Provisioned(_, _))
      .WillOnce([&provisioning_done]() { provisioning_done.Notify(); });

  provision_->Start();

  ASSERT_TRUE(
      provisioning_done.WaitForNotificationWithTimeout(absl::Seconds(1)));

  ASSERT_OK_AND_ASSIGN(auto original_transform_params,
                       provision_->GetTransformParams());
  auto original_ipsec_params = original_transform_params.bridge();

  EXPECT_CALL(egress_manager_, GetEgressNodeForPpnIpSec(PublicMetadataParamsEq(
                                   CreateGetInitialDataResponse())))
      .WillOnce(
          [this](const AddEgressRequest::PpnDataplaneRequestParams& params) {
            EXPECT_EQ(params.dataplane_protocol, config_.datapath_protocol());
            EXPECT_TRUE(params.dynamic_mtu_enabled);
            notification_thread_.Post(
                [this] { provision_->EgressAvailable(/*is_rekey=*/true); });
            return absl::OkStatus();
          });

  EXPECT_CALL(egress_manager_, GetEgressSessionDetails)
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

  ASSERT_OK_AND_ASSIGN(auto ppn_dataplane_response,
                       provisioned_response.ppn_dataplane_response());
  ASSERT_OK_AND_ASSIGN(auto expected_response,
                       fake_rekey_response.ppn_dataplane_response());
  EXPECT_THAT(ppn_dataplane_response, EqualsProto(expected_response));

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
  ASSERT_OK_AND_ASSIGN(auto auth_and_sign_response,
                       CreateAuthAndSignResponse("eu.b.g-tun.com"));

  EXPECT_CALL(auth_, auth_response).WillOnce(Return(auth_and_sign_response));

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

}  // namespace
}  // namespace krypton
}  // namespace privacy
