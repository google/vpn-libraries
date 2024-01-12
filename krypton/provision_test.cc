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
#include "privacy/net/common/proto/beryllium.proto.h"
#include "privacy/net/common/proto/get_initial_data.proto.h"
#include "privacy/net/krypton/add_egress_response.h"
#include "privacy/net/krypton/auth.h"
#include "privacy/net/krypton/crypto/session_crypto.h"
#include "privacy/net/krypton/egress_manager.h"
#include "privacy/net/krypton/json_keys.h"
#include "privacy/net/krypton/pal/mock_http_fetcher_interface.h"
#include "privacy/net/krypton/pal/mock_oauth_interface.h"
#include "privacy/net/krypton/proto/debug_info.proto.h"
#include "privacy/net/krypton/proto/http_fetcher.proto.h"
#include "privacy/net/krypton/proto/krypton_config.proto.h"
#include "privacy/net/krypton/utils/http_response_test_utils.h"
#include "privacy/net/krypton/utils/json_util.h"
#include "privacy/net/krypton/utils/looper.h"
#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/absl/synchronization/notification.h"
#include "third_party/absl/time/time.h"
#include "third_party/anonymous_tokens/cpp/testing/proto_utils.h"
#include "third_party/json/include/nlohmann/json.hpp"
#include "third_party/json/include/nlohmann/json_fwd.hpp"
#include "third_party/openssl/base.h"

namespace privacy {
namespace krypton {
namespace {

using ::privacy::net::common::proto::PpnDataplaneResponse;
using ::proto2::contrib::parse_proto::ParseTextProtoOrDie;
using ::testing::_;
using ::testing::EqualsProto;
using ::testing::Return;
using ::testing::StrEq;
using ::testing::proto::Partially;
using ::testing::status::StatusIs;

MATCHER_P(RequestUrlMatcher, url, "") { return arg.url() == url; }

class MockNotification : public Provision::NotificationInterface {
 public:
  MOCK_METHOD(void, ReadyForAddEgress, (bool), (override));
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

    ASSERT_OK_AND_ASSIGN(key_material_, crypto::SessionCrypto::Create(config_));

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

    ON_CALL(notification_, ReadyForAddEgress)
        .WillByDefault([this](bool is_rekey) {
          provision_->SendAddEgress(is_rekey, key_material_.get());
        });
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
  std::unique_ptr<crypto::SessionCrypto> key_material_;
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
  done.WaitForNotification();

  ASSERT_OK_AND_ASSIGN(std::string control_plane_sockaddr,
                       provision_->GetControlPlaneSockaddr());
  EXPECT_EQ(control_plane_sockaddr, "0.0.0.0:1849");
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

TEST_F(ProvisionTest, UsesIPv6ControlPlaneSockaddrFromAddEgressResponse) {
  // Modify the default AddEgressResponse to include a control plane sockaddr.
  HttpResponse fake_add_egress_response = utils::CreateAddEgressHttpResponse();
  ASSERT_OK_AND_ASSIGN(
      nlohmann::json json_obj,
      utils::StringToJson(fake_add_egress_response.json_body()));
  json_obj[JsonKeys::kPpnDataplane][JsonKeys::kControlPlaneSockAddr] =
      nlohmann::json::array({"[::1]:1234", "127.0.0.1:1234"});
  fake_add_egress_response.set_json_body(utils::JsonToString(json_obj));
  EXPECT_CALL(http_fetcher_, PostJson(RequestUrlMatcher("initial_data")));
  EXPECT_CALL(http_fetcher_, PostJson(RequestUrlMatcher("auth")));
  EXPECT_CALL(http_fetcher_, PostJson(RequestUrlMatcher("add_egress")))
      .WillOnce(Return(fake_add_egress_response));

  absl::Notification done;
  AddEgressResponse provisioned_response;
  EXPECT_CALL(notification_, Provisioned(_, _))
      .WillOnce([&done, &provisioned_response](AddEgressResponse response,
                                               bool /*is_rekey*/) {
        provisioned_response = response;
        done.Notify();
      });

  provision_->Start();
  done.WaitForNotification();

  ASSERT_OK_AND_ASSIGN(std::string control_plane_sockaddr,
                       provision_->GetControlPlaneSockaddr());
  EXPECT_EQ(control_plane_sockaddr, "[::1]:1234");
  ASSERT_OK_AND_ASSIGN(auto actual_ppn_dataplane_response,
                       provisioned_response.ppn_dataplane_response());
  EXPECT_THAT(actual_ppn_dataplane_response, Partially(EqualsProto(R"pb(
                control_plane_sock_addr: "[::1]:1234",
                control_plane_sock_addr: "127.0.0.1:1234",
              )pb")));
}

TEST_F(ProvisionTest, UsesIPv4ControlPlaneSockaddrFromAddEgressResponse) {
  // Modify the default AddEgressResponse to include a control plane sockaddr.
  HttpResponse fake_add_egress_response = utils::CreateAddEgressHttpResponse();
  ASSERT_OK_AND_ASSIGN(
      nlohmann::json json_obj,
      utils::StringToJson(fake_add_egress_response.json_body()));
  json_obj[JsonKeys::kPpnDataplane][JsonKeys::kControlPlaneSockAddr] =
      nlohmann::json::array({"127.0.0.1:1234", "[::1]:1234"});
  fake_add_egress_response.set_json_body(utils::JsonToString(json_obj));
  EXPECT_CALL(http_fetcher_, PostJson(RequestUrlMatcher("initial_data")));
  EXPECT_CALL(http_fetcher_, PostJson(RequestUrlMatcher("auth")));
  EXPECT_CALL(http_fetcher_, PostJson(RequestUrlMatcher("add_egress")))
      .WillOnce(Return(fake_add_egress_response));

  absl::Notification done;
  AddEgressResponse provisioned_response;
  EXPECT_CALL(notification_, Provisioned(_, _))
      .WillOnce([&done, &provisioned_response](AddEgressResponse response,
                                               bool /*is_rekey*/) {
        provisioned_response = response;
        done.Notify();
      });

  provision_->Start();
  done.WaitForNotification();

  ASSERT_OK_AND_ASSIGN(std::string control_plane_sockaddr,
                       provision_->GetControlPlaneSockaddr());
  EXPECT_EQ(control_plane_sockaddr, "127.0.0.1:1234");
  ASSERT_OK_AND_ASSIGN(auto actual_ppn_dataplane_response,
                       provisioned_response.ppn_dataplane_response());
  EXPECT_THAT(actual_ppn_dataplane_response, Partially(EqualsProto(R"pb(
                control_plane_sock_addr: "127.0.0.1:1234",
                control_plane_sock_addr: "[::1]:1234",
              )pb")));
}

TEST_F(ProvisionTest, Rekey) {
  absl::Notification provisioning_done;
  EXPECT_CALL(notification_, Provisioned(_, /*is_rekey=*/false))
      .WillOnce([&provisioning_done]() { provisioning_done.Notify(); });

  absl::Notification rekey_done;
  AddEgressResponse actual_rekey_response;
  EXPECT_CALL(notification_, Provisioned(_, /*is_rekey=*/true))
      .WillOnce([&rekey_done, &actual_rekey_response](
                    AddEgressResponse response, bool /*is_rekey*/) {
        actual_rekey_response = response;
        rekey_done.Notify();
      });

  provision_->Start();

  ASSERT_TRUE(
      provisioning_done.WaitForNotificationWithTimeout(absl::Seconds(1)));

  EXPECT_CALL(http_fetcher_, PostJson(RequestUrlMatcher("initial_data")));
  EXPECT_CALL(http_fetcher_, PostJson(RequestUrlMatcher("auth")));
  HttpResponse fake_rekey_response = utils::CreateRekeyHttpResponse();
  EXPECT_CALL(http_fetcher_, PostJson(RequestUrlMatcher("add_egress")))
      .WillOnce(Return(fake_rekey_response));

  provision_->Rekey();

  ASSERT_TRUE(rekey_done.WaitForNotificationWithTimeout(absl::Seconds(1)));

  ASSERT_OK_AND_ASSIGN(AddEgressResponse expected_rekey_response,
                       AddEgressResponse::FromProto(fake_rekey_response));
  ASSERT_OK_AND_ASSIGN(PpnDataplaneResponse expected_ppn_dataplane_response,
                       expected_rekey_response.ppn_dataplane_response());
  ASSERT_OK_AND_ASSIGN(PpnDataplaneResponse actual_ppn_dataplane_response,
                       actual_rekey_response.ppn_dataplane_response());
  EXPECT_THAT(actual_ppn_dataplane_response,
              EqualsProto(expected_ppn_dataplane_response));
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
