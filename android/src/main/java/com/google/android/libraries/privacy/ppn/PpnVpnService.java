// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the );
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an  BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.google.android.libraries.privacy.ppn;

import android.content.Intent;
import android.net.VpnService;
import android.util.Log;
import com.google.android.libraries.privacy.ppn.internal.PpnLibrary;
import java.io.FileDescriptor;
import java.io.PrintWriter;

/** Provides PPN's VpnService implementation for Android. */
public class PpnVpnService extends VpnService {
  private static final String TAG = "PpnVpnService";

  @Override
  public void onCreate() {
    PpnLibrary.getPpn()
        .onStartService(this)
        .addOnFailureListener(e -> Log.e(TAG, "Failed to start PPN service.", e));
  }

  @Override
  public void onDestroy() {
    PpnLibrary.getPpn().onStopService();
  }

  @Override
  public int onStartCommand(Intent intent, int flags, int startId) {
    return PpnLibrary.getPpn().isStickyService() ? START_STICKY : START_NOT_STICKY;
  }

  @Override
  public void onRevoke() {
    Log.w(TAG, "VPN revoked by user.");
    // This callback means that the user clicked "disconnect" in the system settings or installed a
    // different VPN, so treat it the same as the user turning off PPN from the UI.
    PpnLibrary.getPpn().stop();
  }

  @Override
  protected void dump(FileDescriptor fd, PrintWriter out, String[] args) {}
}
