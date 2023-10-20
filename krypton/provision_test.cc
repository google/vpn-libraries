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
#include "privacy/net/krypton/auth.h"
#include "privacy/net/krypton/egress_manager.h"
#include "privacy/net/krypton/pal/mock_http_fetcher_interface.h"
#include "privacy/net/krypton/pal/mock_oauth_interface.h"
#include "privacy/net/krypton/proto/debug_info.proto.h"
#include "privacy/net/krypton/proto/http_fetcher.proto.h"
#include "privacy/net/krypton/proto/krypton_config.proto.h"
#include "privacy/net/krypton/utils/http_response_test_utils.h"
#include "privacy/net/krypton/utils/looper.h"
#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/absl/synchronization/notification.h"
#include "third_party/absl/time/time.h"
#include "third_party/anonymous_tokens/cpp/testing/proto_utils.h"
#include "third_party/openssl/base.h"

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
    provision_ = std::make_unique<Provision>(
        config_, std::make_unique<Auth>(config_, &http_fetcher_, &oauth_),
        std::make_unique<EgressManager>(config_, &http_fetcher_),
        &http_fetcher_, &notification_, &looper_);

    ASSERT_OK_AND_ASSIGN(
        key_pair_, ::private_membership::anonymous_tokens::CreateTestKey());
    key_pair_.second.set_key_version(1);
    key_pair_.second.set_use_case("TEST_USE_CASE");

    ON_CALL(oauth_, GetAttestationData(_))
        .WillByDefault(Return(ppn::AttestationData()));
    ON_CALL(oauth_, GetOAuthToken).WillByDefault(Return("some_token"));

    ON_CALL(http_fetcher_, LookupDns(_)).WillByDefault(Return("0.0.0.0"));
    ON_CALL(http_fetcher_, PostJson(RequestUrlMatcher("initial_data")))
        .WillByDefault(
            Return(utils::CreateGetInitialDataHttpResponse(key_pair_.second)));
    ON_CALL(http_fetcher_, PostJson(RequestUrlMatcher("auth")))
        .WillByDefault([this](const HttpRequest& http_request) {
          return utils::CreateAuthHttpResponse(http_request,
                                               key_pair_.first.get());
        });
    ON_CALL(http_fetcher_, PostJson(RequestUrlMatcher("add_egress")))
        .WillByDefault(Return(utils::CreateAddEgressHttpResponse()));
  }

  void TearDown() override { provision_->Stop(); }

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
      .WillOnce(Return(utils::CreateHttpResponseWithStatus(500, "Failure")));

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
      .WillOnce(Return(utils::CreateHttpResponseWithStatus(403, "Failure")));

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
      .WillOnce(Return(utils::CreateHttpResponseWithStatus(500, "Failure")));

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
      AddEgressResponse expected_add_egress_response,
      AddEgressResponse::FromProto(utils::CreateAddEgressHttpResponse()));
  ASSERT_OK_AND_ASSIGN(auto expected_ppn_dataplane_response,
                       expected_add_egress_response.ppn_dataplane_response());
  EXPECT_THAT(actual_ppn_dataplane_response,
              EqualsProto(expected_ppn_dataplane_response));
}

TEST_F(ProvisionTest, Rekey) {
  absl::Notification provisioning_done;
  absl::Notification rekey_done;
  HttpResponse fake_rekey_response = utils::CreateRekeyHttpResponse();

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
        return utils::CreateAuthHttpResponse(request, key_pair_.first.get(),
                                             "eu.b.g-tun.com");
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

  EXPECT_CALL(http_fetcher_, LookupDns(StrEq("na4.p.g-tun.com")));

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
