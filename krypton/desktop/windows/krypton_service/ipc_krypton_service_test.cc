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

#include "privacy/net/krypton/desktop/windows/krypton_service/ipc_krypton_service.h"

#include <memory>

#include "google/rpc/code.proto.h"
#include "google/rpc/status.proto.h"
#include "privacy/net/krypton/desktop/proto/krypton_control_message.proto.h"
#include "privacy/net/krypton/desktop/windows/ipc/named_pipe_interface.h"
#include "privacy/net/krypton/desktop/windows/krypton_service/windows_api_interface.h"
#include "privacy/net/krypton/desktop/windows/utils/error.h"
#include "privacy/net/krypton/proto/krypton_config.proto.h"
#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"
#include "third_party/absl/status/status.h"

namespace privacy {
namespace krypton {
namespace windows {

class IpcKryptonServiceTest : public ::testing::Test {
  class MockNamedPipe : public NamedPipeInterface {
   public:
    MockNamedPipe() = default;
    MOCK_METHOD(absl::Status, IpcSendSyncMessage,
                (const desktop::KryptonControlMessage& message), (override));
    MOCK_METHOD(absl::StatusOr<desktop::KryptonControlMessage>,
                IpcReadSyncMessage, (), (override));
    MOCK_METHOD(absl::StatusOr<std::string>, ReadSync,
                (LPOVERLAPPED overlapped), (override));
    MOCK_METHOD(absl::StatusOr<desktop::KryptonControlMessage>, Call,
                (const desktop::KryptonControlMessage& request), (override));
    MOCK_METHOD(absl::Status, WaitForClientToConnect, (), (override));
    MOCK_METHOD(absl::Status, WaitForClientToDisconnect, (), (override));
    MOCK_METHOD(absl::Status, Initialize, (), (override));
    MOCK_METHOD(HANDLE, GetStopPipeEvent, (), (override));
    MOCK_METHOD(void, FlushPipe, (), (override));
  };

  class MockPpnService : public PpnServiceInterface {
   public:
    MOCK_METHOD(absl::StatusOr<desktop::PpnTelemetry>, CollectTelemetry, (),
                (override));
    MOCK_METHOD(absl::Status, SetIpGeoLevel, (privacy::ppn::IpGeoLevel),
                (override));
    MOCK_METHOD(void, Start, (const privacy::krypton::KryptonConfig&),
                (override));
    MOCK_METHOD(void, Stop, (const absl::Status&), (override));
  };

  class MockWindowsApi : public WindowsApiInterface {
   public:
    MOCK_METHOD(DWORD, WaitForSingleObject, (HANDLE handle, DWORD milliseconds),
                (override));
  };

  void SetUp() override {
    ipc_krypton_service = std::make_unique<IpcKryptonService>(
        &mock_ppn_service, &mock_named_pipe, &mock_windows_api);
  }

 protected:
  std::unique_ptr<IpcKryptonService> ipc_krypton_service;
  MockNamedPipe mock_named_pipe;
  MockPpnService mock_ppn_service;
  MockWindowsApi mock_windows_api;
};

TEST_F(IpcKryptonServiceTest, TestReadAndWriteToPipe_ReadFromPipeSuccessful) {
  desktop::KryptonControlMessage request;
  request.set_type(desktop::KryptonControlMessage::START_KRYPTON);
  ON_CALL(mock_named_pipe, IpcReadSyncMessage())
      .WillByDefault(testing::Return(request));
  absl::Status status = ipc_krypton_service->ReadAndWriteToPipe();
  EXPECT_OK(status);
}

TEST_F(IpcKryptonServiceTest, TestReadAndWriteToPipe_ReadFromPipeFailed) {
  ON_CALL(mock_named_pipe, IpcReadSyncMessage())
      .WillByDefault(testing::Return(absl::InternalError("Failed")));
  EXPECT_THAT(ipc_krypton_service->ReadAndWriteToPipe(),
              ::testing::status::StatusIs(absl::StatusCode::kInternal));
}

TEST_F(IpcKryptonServiceTest, TestReadAndWriteToPipe_ValidStartKryptonMessage) {
  desktop::KryptonControlMessage request;
  request.set_type(desktop::KryptonControlMessage::START_KRYPTON);
  KryptonConfig config;
  *(request.mutable_request()
        ->mutable_start_krypton_request()
        ->mutable_krypton_config()) = config;
  EXPECT_CALL(mock_ppn_service, Start(testing::_)).Times(1);
  ON_CALL(mock_named_pipe, IpcReadSyncMessage())
      .WillByDefault(testing::Return(request));
  ipc_krypton_service->ReadAndWriteToPipe();
}

TEST_F(IpcKryptonServiceTest, TestReadAndWriteToPipe_SendToPipeFailed) {
  desktop::KryptonControlMessage request;
  request.set_type(desktop::KryptonControlMessage::START_KRYPTON);
  ON_CALL(mock_named_pipe, IpcReadSyncMessage())
      .WillByDefault(testing::Return(request));
  ON_CALL(mock_named_pipe, IpcSendSyncMessage(testing::_))
      .WillByDefault(testing::Return(absl::InternalError("Failed")));
  EXPECT_THAT(ipc_krypton_service->ReadAndWriteToPipe(),
              ::testing::status::StatusIs(absl::StatusCode::kInternal));
}

TEST_F(IpcKryptonServiceTest, TestReadAndWriteToPipe_CloseEventTriggered) {
  ON_CALL(mock_windows_api, WaitForSingleObject(testing::_, testing::_))
      .WillByDefault(testing::Return(WAIT_OBJECT_0));
  desktop::KryptonControlMessage request;
  request.set_type(
      privacy::krypton::desktop::KryptonControlMessage::START_KRYPTON);
  ON_CALL(mock_named_pipe, IpcReadSyncMessage())
      .WillByDefault(testing::Return(request));
  EXPECT_THAT(ipc_krypton_service->PollOnPipe(),
              testing::status::StatusIs(absl::StatusCode::kCancelled));
}

TEST_F(IpcKryptonServiceTest, TestProcessAppToServiceMessage_ValidStopMessage) {
  desktop::KryptonControlMessage request;
  request.set_type(desktop::KryptonControlMessage::STOP_KRYPTON);
  *(request.mutable_request()
        ->mutable_stop_krypton_request()
        ->mutable_status()) = utils::GetRpcStatusforStatus(absl::OkStatus());
  EXPECT_CALL(mock_ppn_service, Stop(testing::_)).Times(1);
  desktop::KryptonControlMessage response =
      ipc_krypton_service->ProcessKryptonControlMessage(request);
  desktop::KryptonControlMessage expected_response;
  expected_response.set_type(desktop::KryptonControlMessage::STOP_KRYPTON);
  google::rpc::Status* status = new google::rpc::Status();
  status->set_code(google::rpc::Code::OK);
  expected_response.mutable_response()->set_allocated_status(status);
  EXPECT_THAT(response, testing::EqualsProto(expected_response));
}

TEST_F(IpcKryptonServiceTest,
       TestProcessAppToServiceMessage_InvalidStartMessage) {
  desktop::KryptonControlMessage request;
  request.set_type(desktop::KryptonControlMessage::START_KRYPTON);
  EXPECT_CALL(mock_ppn_service, Start(testing::_)).Times(0);
  desktop::KryptonControlMessage response =
      ipc_krypton_service->ProcessKryptonControlMessage(request);
  EXPECT_EQ(response.response().status().code(), google::rpc::Code::INTERNAL);
}

TEST_F(IpcKryptonServiceTest,
       TestProcessAppToServiceMessage_InvalidStopMessage) {
  desktop::KryptonControlMessage request;
  request.set_type(desktop::KryptonControlMessage::STOP_KRYPTON);
  EXPECT_CALL(mock_ppn_service, Stop(testing::_)).Times(0);
  desktop::KryptonControlMessage response =
      ipc_krypton_service->ProcessKryptonControlMessage(request);
  EXPECT_EQ(response.response().status().code(), google::rpc::Code::INTERNAL);
}

TEST_F(IpcKryptonServiceTest,
       TestProcessAppToServiceMessage_InvalidDefaultMessage) {
  desktop::KryptonControlMessage request;
  request.set_type(desktop::KryptonControlMessage::MESSAGE_TYPE_UNSPECIFIED);
  desktop::KryptonControlMessage response =
      ipc_krypton_service->ProcessKryptonControlMessage(request);
  EXPECT_EQ(response.response().status().code(),
            google::rpc::Code::UNIMPLEMENTED);
  EXPECT_EQ(response.response().status().message(),
            "This message type is not supported yet");
}

}  // namespace windows
}  // namespace krypton
}  // namespace privacy
