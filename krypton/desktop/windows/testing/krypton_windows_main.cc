// Copyright 2022 Google LLC
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

#include <windows.h>

#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "base/init_google.h"
#include "privacy/net/krypton/desktop/desktop_oauth.h"
#include "privacy/net/krypton/desktop/proto/oauth.proto.h"
#include "privacy/net/krypton/desktop/windows/http_fetcher.h"
#include "privacy/net/krypton/desktop/windows/local_secure_storage_windows.h"
#include "privacy/net/krypton/desktop/windows/network_monitor.h"
#include "privacy/net/krypton/desktop/windows/notification.h"
#include "privacy/net/krypton/desktop/windows/testing/fake_oauth.h"
#include "privacy/net/krypton/desktop/windows/testing/resource.h"
#include "privacy/net/krypton/desktop/windows/timer.h"
#include "privacy/net/krypton/desktop/windows/utils/error.h"
#include "privacy/net/krypton/desktop/windows/vpn_service.h"
#include "privacy/net/krypton/desktop/windows/xenon/network_debug.h"
#include "privacy/net/krypton/krypton.h"
#include "privacy/net/krypton/krypton_clock.h"
#include "privacy/net/krypton/proto/krypton_config.proto.h"
#include "privacy/net/krypton/proto/krypton_telemetry.proto.h"
#include "privacy/net/krypton/proto/network_info.proto.h"
#include "privacy/net/krypton/timer_manager.h"
#include "privacy/net/krypton/utils/looper.h"
#include "third_party/absl/base/thread_annotations.h"
#include "third_party/absl/flags/flag.h"
#include "third_party/absl/memory/memory.h"
#include "third_party/absl/strings/str_cat.h"
#include "third_party/absl/strings/str_format.h"
#include "third_party/absl/strings/str_join.h"
#include "third_party/absl/strings/str_split.h"
#include "third_party/absl/synchronization/mutex.h"

ABSL_FLAG(std::string, zinc_addr, "https://staging.zinc.cloud.cupronickel.goog",
          "zinc DNS address");
ABSL_FLAG(std::string, brass_addr,
          "https://staging.brass.cloud.cupronickel.goog", "brass DNS address");
ABSL_FLAG(std::string, copper_addr, "na4.p.g-tun.com",
          "Copper Controller DNS address");
ABSL_FLAG(std::string, oauth_token, "", "Valid OAuth token");
ABSL_FLAG(bool, safe_disconnect, false, "Enable safe disconnect");

namespace privacy::krypton::windows {

// A message that tells the UI to update all of its fields.
constexpr int WM_UPDATE_STATUS = WM_APP + 1;

/**
 * Krypton relies on a bunch of other state staying in memory while it runs, so
 * we run it in a background thread, and track the thread and krypton here.
 */
class KryptonState : public NetworkMonitor::NotificationInterface,
                     public privacy::krypton::KryptonNotificationInterface {
 public:
  KryptonState();

  void Stop() {
      xenon_->Stop();
      krypton_->Stop();
      SetStatus("Stopped");
  }

  void CollectTelemetry() {
    SetTelemetry("Collecting...");
    KryptonTelemetry telemetry;
    krypton_->CollectTelemetry(&telemetry);
    SetTelemetry(telemetry.DebugString());
  }

  void BestNetworkChanged(std::optional<NetworkInfo> network) override {
    if (network) {
      LOG(INFO) << "Setting network.";
      PPN_LOG_IF_ERROR(krypton_->SetNetwork(*network));
      SetNetwork(absl::StrFormat(
          "interface %d, type: %s", network->network_id(),
          xenon::GetNetworkTypeDebugString(network->network_type())));
    } else {
      LOG(INFO) << "Setting no network.";
      PPN_LOG_IF_ERROR(krypton_->SetNoNetworkAvailable());
      SetNetwork("<none>");
    }
  }

  void Connected(const krypton::ConnectionStatus& status) override {
    LOG(INFO) << "PPN is connected: " << status.DebugString();
    SetStatus("Connected");
  }

  void Connecting(const krypton::ConnectingStatus& status) override {
    LOG(INFO) << "PPN is connecting: " << status.DebugString();
    SetStatus("Connecting");
  }

  void ControlPlaneConnected() override {
    LOG(INFO) << "ControlPlaneConnected event";
  }

  void StatusUpdated(const krypton::ConnectionStatus& status) override {
    LOG(ERROR) << "PPN status updated: " << status.DebugString();
  }

  void Disconnected(const krypton::DisconnectionStatus& status) override {
    LOG(ERROR) << "PPN is disconnected: " << status.DebugString();
    SetStatus(absl::StrFormat("Disconnected: %d: %s", status.code(),
                              status.message()));
  }

  void NetworkDisconnected(const krypton::NetworkInfo& /* network_info */,
                           const absl::Status& status) override {
    LOG(ERROR) << "PPN's network is disconnected: " << status;
  }

  void PermanentFailure(const absl::Status& status) override {
    LOG(ERROR) << "PPN failed: " << status;
    SetStatus(absl::StrCat("Permanently failed: ", status.ToString()));
  }

  void Crashed() override { LOG(ERROR) << "PPN is crashing."; }

  void Snoozed(const krypton::SnoozeStatus& status) override {
    LOG(INFO) << "PPN is snoozed: " << status.DebugString();
    SetStatus("Snoozed");
  }

  void Resumed(const krypton::ResumeStatus& status) override {
    LOG(INFO) << "Ppn is resumed: " << status.DebugString();
    SetStatus("Resumed");
  }

  void WaitingToReconnect(const krypton::ReconnectionStatus& status) override {
    LOG(INFO) << "WaitingToReconnect event: " << status.DebugString();
    SetStatus("Waiting to reconnect");
  }

  void SetDialog(HWND dialog) {
    {
      absl::MutexLock l(&mutex_);
      dialog_ = dialog;
    }
    UpdateDialog();
  }

  std::string status() {
    absl::MutexLock l(&mutex_);
    return status_;
  }

  void SetStatus(const std::string& status) {
    {
      absl::MutexLock l(&mutex_);
      LOG(INFO) << "Setting status: " << status;
      status_ = status;
    }
    UpdateDialog();
  }

  std::string network() {
    absl::MutexLock l(&mutex_);
    return network_;
  }

  void SetNetwork(const std::string& network) {
    {
      absl::MutexLock l(&mutex_);
      LOG(INFO) << "Setting network: " << network;
      network_ = network;
    }
    UpdateDialog();
  }

  std::string telemetry() {
    absl::MutexLock l(&mutex_);
    return telemetry_;
  }

  void SetTelemetry(const std::string& telemetry) {
    {
      absl::MutexLock l(&mutex_);
      LOG(INFO) << "Setting telemetry: " << telemetry;
      telemetry_ = telemetry;
    }
    UpdateDialog();
  }

 private:
  void UpdateDialog() {
    absl::MutexLock l(&mutex_);
    if (dialog_ == nullptr) {
      return;
    }
    dialog_looper_.Post([dialog = dialog_]() {
      SendNotifyMessage(dialog, WM_UPDATE_STATUS, 0, 0);
    });
  }

  HttpFetcher http_fetcher_;
  VpnService vpn_service_;
  FakeOAuth oauth_;
  TimerManager timer_manager_;

  std::unique_ptr<Krypton> krypton_;
  krypton::utils::LooperThread krypton_looper_{"Krypton Looper"};
  krypton::utils::LooperThread xenon_looper_{"Xenon Looper"};
  std::unique_ptr<NetworkMonitor> xenon_;

  // A looper for sending window messages without blocking.
  krypton::utils::LooperThread dialog_looper_{"Dialog Looper"};

  // State shared with the UI.
  absl::Mutex mutex_;
  HWND dialog_ ABSL_GUARDED_BY(mutex_) = nullptr;
  std::string status_ ABSL_GUARDED_BY(mutex_);
  std::string network_ ABSL_GUARDED_BY(mutex_);
  std::string telemetry_ ABSL_GUARDED_BY(mutex_);
};

KryptonState::KryptonState()
    : oauth_(absl::GetFlag(FLAGS_oauth_token)), timer_manager_(Timer::Get()) {
  PPN_LOG_IF_ERROR(vpn_service_.InitializeWintun());

  krypton_ = std::make_unique<Krypton>(&http_fetcher_, this, &vpn_service_,
                                       &oauth_, &timer_manager_);

  xenon_ = std::make_unique<NetworkMonitor>();
  xenon_->RegisterNotificationHandler(this, &xenon_looper_);

  privacy::krypton::KryptonConfig config;
  config.set_zinc_url(absl::StrCat(absl::GetFlag(FLAGS_zinc_addr), "/auth"));
  config.set_brass_url(
      absl::StrCat(absl::GetFlag(FLAGS_brass_addr), "/addegress"));
  config.set_service_type("g1");
  config.set_copper_controller_address(absl::GetFlag(FLAGS_copper_addr));
  config.add_copper_hostname_suffix("g-tun.com");
  config.set_zinc_public_signing_key_url(
      absl::StrCat(absl::GetFlag(FLAGS_zinc_addr), "/publickey"));
  config.set_safe_disconnect_enabled(absl::GetFlag(FLAGS_safe_disconnect));

  krypton_looper_.Post([this, config]() {
    SetStatus("Started");
    krypton_->Start(config);
    PPN_LOG_IF_ERROR(xenon_->Start());

    LOG(INFO) << "Looper waiting for krypton to stop.";
    krypton_->WaitForTermination();
  });
}

void SetTextBox(HWND hwnd, int textbox, const std::string& text) {
  // This method replaces the "\n" with "\r\n" so that we can set a regular
  // string into a Windows control.
  auto parts = absl::StrSplit(text, "\n");
  auto joined = absl::StrJoin(parts, "\r\n");
  SetDlgItemTextA(hwnd, textbox, joined.c_str());
}

INT_PTR CALLBACK DialogHandler(HWND hwnd, UINT message, WPARAM wparam,
                               LPARAM lparam) {
  static KryptonState* krypton = nullptr;

  switch (message) {
    case WM_INITDIALOG:
      krypton = reinterpret_cast<KryptonState*>(lparam);
      krypton->SetDialog(hwnd);
      break;

    case WM_UPDATE_STATUS:
      SetTextBox(hwnd, IDC_STATUS, krypton->status());
      SetTextBox(hwnd, IDC_NETWORK, krypton->network());
      SetTextBox(hwnd, IDC_TELEMETRY, krypton->telemetry());
      break;

    case WM_COMMAND:
      switch (LOWORD(wparam)) {
        case IDC_COLLECT_TELEMETRY:
          LOG(INFO) << "Collecting Telemetry.";
          krypton->CollectTelemetry();
          break;

        case IDC_QUIT:
          LOG(INFO) << "Stopping Krypton.";
          EndDialog(hwnd, wparam);
          return TRUE;
      }
      break;

    case WM_CLOSE:
      std::cout << "Stopping Krypton." << std::endl;
      EndDialog(hwnd, wparam);
      return TRUE;
  }
  return FALSE;
}

}  // namespace privacy::krypton::windows

int main(int argc, char* argv[]) {
  InitGoogle(argv[0], &argc, &argv, /*remove_flags=*/true);

  if (absl::GetFlag(FLAGS_oauth_token).empty()) {
    LOG(ERROR) << "Required flag missing: --oauth_token";
    return -1;
  }

  LOG(INFO) << "Creating krypton.";
  privacy::krypton::windows::KryptonState krypton_state;

  LOG(INFO) << "Creating test window.";
  auto result = DialogBoxParamA(nullptr, MAKEINTRESOURCEA(IDD_DIALOG1), nullptr,
                                privacy::krypton::windows::DialogHandler,
                                reinterpret_cast<LPARAM>(&krypton_state));
  if (result == -1) {
    auto status = privacy::krypton::windows::utils::GetStatusForError(
        "Unable to show dialog", GetLastError());
    LOG(ERROR) << status;
  }

  LOG(INFO) << "Stopping krypton.";
  krypton_state.Stop();

  return 0;
}
