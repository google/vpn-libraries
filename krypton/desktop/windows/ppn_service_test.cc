/*
 * Copyright (C) 2022 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "privacy/net/krypton/desktop/windows/ppn_service.h"

#include <memory>
#include <string>
#include <utility>

#include "privacy/net/krypton/desktop/windows/ipc/named_pipe_interface.h"
#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"

namespace privacy {
namespace krypton {
namespace windows {
namespace {

class PpnServiceTest : public ::testing::Test {
  class MockNamedPipeFactory : public NamedPipeFactoryInterface {
   public:
    MOCK_METHOD(absl::StatusOr<std::unique_ptr<NamedPipeInterface>>,
                ConnectToPipeOnServer, (const std::string& pipe_name),
                (override, const));
    MOCK_METHOD(absl::StatusOr<std::unique_ptr<NamedPipeInterface>>,
                CreateNamedPipeInstance, (const std::string& pipe_name),
                (override, const));
  };

 protected:
  MockNamedPipeFactory mock_named_pipe_factory_;
};

TEST_F(PpnServiceTest, PpnServiceCreateFailsFatalOnPipes) {
  ON_CALL(mock_named_pipe_factory_, CreateNamedPipeInstance(testing::_))
      .WillByDefault([] { return absl::InternalError(""); });
  EXPECT_DEATH(windows::PpnService::Create(nullptr, nullptr, nullptr,
                                           mock_named_pipe_factory_),
               testing::HasSubstr("Check failed: app_to_service_pipe"));
}

TEST_F(PpnServiceTest, PpnServiceCreateFailsFatalOnService) {
  absl::StatusOr<std::unique_ptr<NamedPipeInterface>> named_pipe =
      absl::StatusOr<std::unique_ptr<NamedPipeInterface>>(
          absl::in_place_t(), std::make_unique<NamedPipe>());
  ON_CALL(mock_named_pipe_factory_, CreateNamedPipeInstance(testing::_))
      .WillByDefault([] { return std::make_unique<NamedPipe>(); });
  ON_CALL(mock_named_pipe_factory_, CreateNamedPipeInstance(testing::_))
      .WillByDefault([] { return std::make_unique<NamedPipe>(); });

  EXPECT_DEATH(
      windows::PpnService::Create(nullptr, nullptr, nullptr,
                                  mock_named_pipe_factory_),
      testing::HasSubstr("Failed to create a service handle with error"));
}

}  // namespace
}  // namespace windows
}  // namespace krypton
}  // namespace privacy
