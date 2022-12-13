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

#include <memory>
#include <string>

#include "base/init_google.h"
#include "google/rpc/status.proto.h"
#include "privacy/net/krypton/desktop/proto/krypton_control_message.proto.h"
#include "privacy/net/krypton/desktop/windows/ipc/named_pipe.h"
#include "privacy/net/krypton/desktop/windows/ipc/named_pipe_factory.h"
#include "privacy/net/krypton/desktop/windows/utils/event.h"
#include "privacy/net/krypton/utils/looper.h"
#include "privacy/net/krypton/utils/status.h"
#include "third_party/absl/log/log.h"

int main(int argc, char* argv[]) {
  InitGoogle(argv[0], &argc, &argv, true);
  std::string kIpcTestPipeName = "\\\\.\\PIPE\\testPipe";

  auto server_thread =
      std::make_unique<privacy::krypton::utils::LooperThread>("Server  Looper");
  auto client_thread =
      std::make_unique<privacy::krypton::utils::LooperThread>("Client Looper");

  server_thread->Post([kIpcTestPipeName] {
    privacy::krypton::windows::NamedPipeFactory named_pipe_factory;
    auto named_pipe =
        *named_pipe_factory.CreateNamedPipeInstance(kIpcTestPipeName);
    PPN_LOG_IF_ERROR(named_pipe->WaitForClientToConnect());

    privacy::krypton::desktop::KryptonControlMessage request;
    request = *named_pipe->IpcReadSyncMessage();
    LOG(INFO) << "Server: Request from Client: " << request.DebugString();
    privacy::krypton::desktop::KryptonControlMessage response;
    privacy::krypton::desktop::KryptonControlResponse krytpon_control_response;
    response.set_allocated_response(&krytpon_control_response);
    LOG(INFO) << "Server: Response message to Client: "
              << response.DebugString();
    absl::Status write_status = named_pipe->IpcSendSyncMessage(response);
    if (!write_status.ok()) {
      LOG(ERROR) << "Can't send IPC message with error: " << write_status;
    }
  });

  client_thread->Post([kIpcTestPipeName] {
    LOG(INFO) << "Looper Thread: Creatfile Client";
    privacy::krypton::windows::NamedPipeFactory named_pipe_factory;
    auto named_pipe =
        *named_pipe_factory.ConnectToPipeOnServer(kIpcTestPipeName);
    privacy::krypton::desktop::KryptonControlMessage request;
    request.set_type(
        privacy::krypton::desktop::KryptonControlMessage::START_KRYPTON);
    auto response_status = named_pipe->Call(request);
    if (!response_status.ok()) {
      LOG(ERROR) << "Client: Error connecting to the server: "
                 << response_status.status();
      return;
    }
    privacy::krypton::desktop::KryptonControlMessage response =
        *response_status;
    LOG(INFO) << "Client: Response from Server: " << response.DebugString();
  });

  LOG(INFO) << "Ipc Named Pipe Test is running. Press any key to stop....";
  auto ch = getchar();
  client_thread->Stop();
  client_thread->Join();
  server_thread->Stop();
  server_thread->Join();
  return 0;
}
