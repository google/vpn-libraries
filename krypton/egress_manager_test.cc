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

#include "privacy/net/krypton/egress_manager.h"

#include <cstdint>
#include <memory>
#include <string>

#include "privacy/net/krypton/add_egress_request.h"
#include "privacy/net/krypton/crypto/session_crypto.h"
#include "privacy/net/krypton/json_keys.h"
#include "privacy/net/krypton/pal/mock_http_fetcher_interface.h"
#include "privacy/net/krypton/proto/debug_info.proto.h"
#include "privacy/net/krypton/proto/krypton_config.proto.h"
#include "privacy/net/krypton/utils/json_util.h"
#include "privacy/net/krypton/utils/looper.h"
#include "privacy/net/krypton/utils/status.h"
#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/absl/synchronization/notification.h"
#include "third_party/json/include/nlohmann/json.hpp"

namespace privacy {
namespace krypton {

using ::testing::EqualsProto;
using ::testing::InvokeWithoutArgs;
using ::testing::Return;

// Mock interface for Notification.  Used for testing.
class MockEgressManagerNotification
    : public EgressManager::NotificationInterface {
 public:
  MOCK_METHOD(void, EgressAvailable, (bool), (override));
  MOCK_METHOD(void, EgressUnavailable, (const absl::Status&), (override));
};

class EgressManagerTest : public ::testing::Test {
 public:
  MockEgressManagerNotification mock_notification_;
  KryptonConfig config_;
  crypto::SessionCrypto crypto_{config_};

  void SetUp() override {
    config_.set_brass_url("http://www.example.com/addegress");
    config_.add_copper_hostname_suffix("g-tun.com");
  }

  absl::StatusOr<HttpRequest> BuildAddEgressRequestPpnIpSec(
      absl::string_view url, uint32_t spi) {
    HttpRequest request;
    request.set_url(url);
    PPN_ASSIGN_OR_RETURN(auto json_body,
                         BuildJsonBodyForAddEgressRequestPpnIpSec(spi));
    request.set_json_body(json_body);
    return request;
  }

  // Request from AddEgress.
  absl::StatusOr<std::string> BuildJsonBodyForAddEgressRequestPpnIpSec(
      uint32_t spi) {
    PPN_ASSIGN_OR_RETURN(auto expected, utils::StringToJson(R"string({
      "ppn" : {
      },
      "unblinded_token" : "",
      "unblinded_token_signature": "",
      "region_token_and_signature" : ""
    })string"));

    auto keys = crypto_.GetMyKeyMaterial();
    expected[JsonKeys::kPpn][JsonKeys::kClientNonce] = keys.nonce;
    expected[JsonKeys::kPpn][JsonKeys::kClientPublicValue] = keys.public_value;
    expected[JsonKeys::kPpn][JsonKeys::kControlPlaneSockAddr] =
        "192.168.0.10:1849";
    expected[JsonKeys::kPpn][JsonKeys::kApnType] = "ppn";

    expected[JsonKeys::kPpn][JsonKeys::kDownlinkSpi] = spi;
    expected[JsonKeys::kPpn][JsonKeys::kSuite] = "AES128_GCM";
    expected[JsonKeys::kPpn][JsonKeys::kDataplaneProtocol] = "IPSEC";
    expected[JsonKeys::kPpn][JsonKeys::kRekeyVerificationKey] =
        crypto_.GetRekeyVerificationKey().ValueOrDie();
    return utils::JsonToString(expected);
  }

  absl::StatusOr<HttpResponse> BuildAddEgressResponseForPpnIpSec() {
    crypto::SessionCrypto server_crypto(config_);
    auto keys = crypto_.GetMyKeyMaterial();
    PPN_ASSIGN_OR_RETURN(auto json_body, utils::StringToJson(R"json({
      "ppn_dataplane": {
        "user_private_ip": [{
          "ipv4_range": "127.0.0.1"
        }],
        "egress_point_sock_addr": [
          "addr1"
        ],
        "egress_point_public_value": "1234567890abcdef",
        "server_nonce": "abcd",
        "uplink_spi": 123,
        "expiry": "2020-08-07T01:06:13+00:00"
      }
    })json"));
    json_body[JsonKeys::kPpn][JsonKeys::kEgressPointPublicValue] =
        keys.public_value;
    json_body[JsonKeys::kPpn][JsonKeys::kServerNonce] = keys.nonce;

    HttpResponse response;
    response.mutable_status()->set_code(200);
    response.mutable_status()->set_message("OK");
    response.set_json_body(utils::JsonToString(json_body));
    return response;
  }
  utils::LooperThread looper_thread_{"EgressManager Test"};
};

TEST_F(EgressManagerTest, SuccessfulEgressForPpnIpSec) {
  MockHttpFetcher http_fetcher;

  EgressManager egress_manager(config_, &http_fetcher, &looper_thread_);
  egress_manager.RegisterNotificationHandler(&mock_notification_);

  absl::Notification http_fetcher_done;

  ASSERT_OK_AND_ASSIGN(
      auto request_proto,
      BuildAddEgressRequestPpnIpSec("http://www.example.com/addegress",
                                    crypto_.downlink_spi()));
  ASSERT_OK_AND_ASSIGN(auto response_proto,
                       BuildAddEgressResponseForPpnIpSec());
  EXPECT_CALL(http_fetcher, PostJson(EqualsProto(request_proto)))
      .WillOnce(Return(response_proto));

  EXPECT_CALL(mock_notification_, EgressAvailable)
      .WillOnce(
          InvokeWithoutArgs(&http_fetcher_done, &absl::Notification::Notify));

  AddEgressRequest::PpnDataplaneRequestParams params;
  params.crypto = &crypto_;
  params.copper_control_plane_address = "192.168.0.10";
  params.dataplane_protocol = KryptonConfig::IPSEC;
  params.suite = ppn::PpnDataplaneRequest::AES128_GCM;
  params.is_rekey = false;
  params.apn_type = "ppn";

  ASSERT_OK(egress_manager.GetEgressNodeForPpnIpSec(params));

  http_fetcher_done.WaitForNotification();

  EXPECT_EQ(egress_manager.GetState(),
            EgressManager::State::kEgressSessionCreated);

  egress_manager.Stop();
}

}  // namespace krypton
}  // namespace privacy
