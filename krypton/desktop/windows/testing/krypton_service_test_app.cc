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
#include "google/rpc/code.proto.h"
#include "google/rpc/status.proto.h"
#include "privacy/net/krypton/desktop/proto/krypton_control_message.proto.h"
#include "privacy/net/krypton/desktop/windows/ipc/named_pipe.h"
#include "privacy/net/krypton/desktop/windows/ipc/named_pipe_factory.h"
#include "privacy/net/krypton/proto/krypton_config.proto.h"
#include "privacy/net/krypton/utils/looper.h"
#include "privacy/net/krypton/utils/status.h"
#include "third_party/absl/cleanup/cleanup.h"
#include "third_party/absl/log/log.h"

/**
 * Dummy Test app for testing IPC with Krypton Service.
 **/
int main(int argc, char* argv[]) {
  InitGoogle(argv[0], &argc, &argv, true);
  static constexpr const auto kAppToServicePipeName =
      "\\\\.\\PIPE\\vpnbygoogleoneapptoservicepipe";
  static constexpr const auto kServiceToAppPipeName =
      "\\\\.\\PIPE\\vpnbygoogleoneservicetoapppipe";

  auto client_thread =
      std::make_unique<privacy::krypton::utils::LooperThread>("Client Looper");
  auto server_thread =
      std::make_unique<privacy::krypton::utils::LooperThread>("Server Looper");
  privacy::krypton::windows::NamedPipeFactory named_pipe_factory;
  auto app_to_service_named_pipe =
      *named_pipe_factory.CreateNamedPipeInstance(kAppToServicePipeName);
  auto service_to_app_named_pipe =
      *named_pipe_factory.CreateNamedPipeInstance(kServiceToAppPipeName);
  HANDLE close_loop_event =
      *privacy::krypton::windows::utils::CreateManualResetEvent();
  client_thread->Post([&app_to_service_named_pipe] {
    PPN_LOG_IF_ERROR(app_to_service_named_pipe->WaitForClientToConnect());
    LOG(INFO) << "Looper Thread: Creatfile Client";
    {
      privacy::krypton::desktop::KryptonControlMessage request;
      request.set_type(
          privacy::krypton::desktop::KryptonControlMessage::START_KRYPTON);

      // Static Krypton Configs
      privacy::krypton::KryptonConfig config;
      config.set_zinc_url(
          absl::StrCat("https://staging.zinc.cloud.cupronickel.goog", "/auth"));
      config.set_brass_url(absl::StrCat(
          "https://staging.brass.cloud.cupronickel.goog", "/addegress"));
      config.set_service_type("g1");
      config.set_copper_controller_address("na.b.g-tun.com");
      config.add_copper_hostname_suffix("g-tun.com");
      config.set_zinc_public_signing_key_url(absl::StrCat(
          "https://staging.zinc.cloud.cupronickel.goog", "/publickey"));
      config.set_safe_disconnect_enabled(false);

      *(request.mutable_request()
            ->mutable_start_krypton_request()
            ->mutable_krypton_config()) = config;

      auto response_status = app_to_service_named_pipe->Call(request);
      if (!response_status.ok()) {
        LOG(ERROR) << "Client: Error connecting to the server: "
                   << response_status.status();
        return;
      }
      privacy::krypton::desktop::KryptonControlMessage response =
          *response_status;
      LOG(INFO) << "Client: Response from Server: " << response.DebugString();
    }
    // Collecting telemetry at 10 second intervals
    for (int i = 0; i < 10; i++) {
      Sleep(10000);
      privacy::krypton::desktop::KryptonControlMessage request;
      request.set_type(
          privacy::krypton::desktop::KryptonControlMessage::COLLECT_TELEMETRY);
      auto response_status = app_to_service_named_pipe->Call(request);
      if (!response_status.ok()) {
        LOG(ERROR) << "Client: Error connecting to the server: "
                   << response_status.status();
        return;
      }
      privacy::krypton::desktop::KryptonControlMessage response =
          *response_status;
      LOG(INFO) << "Client: Response from Server: " << response.DebugString();
    }
    {
      privacy::krypton::desktop::KryptonControlMessage request;
      request.set_type(
          privacy::krypton::desktop::KryptonControlMessage::STOP_KRYPTON);
      auto response_status = app_to_service_named_pipe->Call(request);
      if (!response_status.ok()) {
        LOG(ERROR) << "Client: Error connecting to the server: "
                   << response_status.status();
        return;
      }
    }
  });

  server_thread->Post([&service_to_app_named_pipe, close_loop_event] {
    PPN_LOG_IF_ERROR(service_to_app_named_pipe->WaitForClientToConnect());
    while (WaitForSingleObject(close_loop_event, 0) == WAIT_TIMEOUT) {
      auto request_status = service_to_app_named_pipe->IpcReadSyncMessage();
      if (!request_status.ok()) {
        LOG(ERROR) << "Client: Error connecting to the server: "
                   << request_status.status();
        return;
      }
      privacy::krypton::desktop::KryptonControlMessage request_message =
          *request_status;
      LOG(INFO) << "Read the message." << request_message.DebugString();

      privacy::krypton::desktop::KryptonControlMessage response;
      if (request_message.type() ==
          privacy::krypton::desktop::KryptonControlMessage::FETCH_OAUTH_TOKEN) {
        response.set_type(privacy::krypton::desktop::KryptonControlMessage::
                              FETCH_OAUTH_TOKEN);
        privacy::krypton::desktop::FetchOauthTokenResponse oauth_response;
        oauth_response.set_oauth_token("<<oauth_token>>");
        *(response.mutable_response()->mutable_fetch_outh_token_response()) =
            oauth_response;
      } else if (request_message.type() ==
                 privacy::krypton::desktop::KryptonControlMessage::
                     NOTIFICATION_UPDATE) {
        response.set_type(privacy::krypton::desktop::KryptonControlMessage::
                              NOTIFICATION_UPDATE);
        google::rpc::Status* status = new google::rpc::Status();
        status->set_code(google::rpc::Code::OK);
        response.mutable_response()->set_allocated_status(status);
      }
      service_to_app_named_pipe->IpcSendSyncMessage(response);
      LOG(INFO) << "Sent a message." << response.DebugString();
    }
  });

  LOG(INFO) << "Client App is running. Press any key to stop....";
  auto ch = getchar();
  SetEvent(close_loop_event);
  client_thread->Stop();
  client_thread->Join();
  server_thread->Stop();
  server_thread->Join();
  return 0;
}
