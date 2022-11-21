// Copyright 2021 Google LLC
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

#include "privacy/net/krypton/datapath/ipsec/ipsec_decryptor.h"
#include "privacy/net/krypton/datapath/ipsec/ipsec_encryptor.h"
#include "privacy/net/krypton/pal/packet.h"
#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace ipsec {
namespace {

class IpSecEncapDecapTest : public ::testing::Test {
 public:
  explicit IpSecEncapDecapTest() {
    auto ip_sec_transform_params = params_.mutable_ipsec();
    ip_sec_transform_params->set_uplink_key(std::string(32, 'z'));
    ip_sec_transform_params->set_downlink_key(std::string(32, 'z'));
    ip_sec_transform_params->set_uplink_salt(std::string(4, 'a'));
    ip_sec_transform_params->set_downlink_salt(std::string(4, 'a'));
  }

  TransformParams params_ = TransformParams();
};

TEST_F(IpSecEncapDecapTest, TestPacketsWithPaddingAreHandledCorrectly) {
  const Packet packet("foo", 3, IPProtocol::kIPv4, [] {});

  ASSERT_OK_AND_ASSIGN(auto encryptor, Encryptor::Create(2, params_));
  ASSERT_OK_AND_ASSIGN(auto decryptor, Decryptor::Create(params_));

  auto encryptedPacket = encryptor->Process(packet);
  EXPECT_OK(encryptedPacket);
  EXPECT_NE(encryptedPacket->data(), packet.data());
  auto decryptedPacket = decryptor->Process(encryptedPacket.value());
  EXPECT_OK(decryptedPacket);

  EXPECT_EQ(decryptedPacket->data(), packet.data());
  EXPECT_EQ(decryptedPacket->protocol(), packet.protocol());
}

TEST_F(IpSecEncapDecapTest, TestPacketsWithoutPaddingAreHandledCorrectly) {
  const Packet packet("fooooooooooooo", 14, IPProtocol::kIPv4, [] {});

  ASSERT_OK_AND_ASSIGN(auto encryptor, Encryptor::Create(2, params_));
  ASSERT_OK_AND_ASSIGN(auto decryptor, Decryptor::Create(params_));

  auto encryptedPacket = encryptor->Process(packet);
  EXPECT_OK(encryptedPacket);
  EXPECT_NE(encryptedPacket->data(), packet.data());
  auto decryptedPacket = decryptor->Process(encryptedPacket.value());
  EXPECT_OK(decryptedPacket);

  EXPECT_EQ(decryptedPacket->data(), packet.data());
  EXPECT_EQ(decryptedPacket->protocol(), packet.protocol());
}

}  // namespace
}  // namespace ipsec
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy
