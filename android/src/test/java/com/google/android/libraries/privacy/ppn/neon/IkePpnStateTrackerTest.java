// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "LICENSE");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS-IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.google.android.libraries.privacy.ppn.neon;

import static com.google.common.truth.Truth.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.robolectric.Shadows.shadowOf;

import android.accounts.Account;
import android.os.Looper;
import com.google.android.gms.auth.GoogleAuthUtil;
import com.google.android.libraries.privacy.ppn.PpnConnectionStatus;
import com.google.android.libraries.privacy.ppn.PpnDisconnectionStatus;
import com.google.android.libraries.privacy.ppn.PpnListener;
import com.google.android.libraries.privacy.ppn.PpnResumeStatus;
import com.google.android.libraries.privacy.ppn.PpnSnoozeStatus;
import com.google.android.libraries.privacy.ppn.PpnStatus;
import com.google.android.libraries.privacy.ppn.PpnStatus.Code;
import com.google.android.libraries.privacy.ppn.neon.IkePpnStateTracker.VpnExternalState;
import com.google.android.libraries.privacy.ppn.neon.IkePpnStateTracker.VpnInternalState;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;
import org.robolectric.RobolectricTestRunner;

@RunWith(RobolectricTestRunner.class)
public final class IkePpnStateTrackerTest {
  private static final String TEST_ACCOUNT_NAME = "test@example.com";

  @Rule public final MockitoRule mockito = MockitoJUnit.rule();

  @Mock private PpnListener mockPpnListener;

  private Account account;

  private IkePpnStateTracker ikePpnStateTracker;

  @Before
  public void setUp() {
    account = new Account(TEST_ACCOUNT_NAME, GoogleAuthUtil.GOOGLE_ACCOUNT_TYPE);
    ikePpnStateTracker = IkePpnStateTracker.getInstance();
    ikePpnStateTracker.setListener(mockPpnListener);
  }

  @Test
  public void ikePpnStateTracker_lifecycle() throws Exception {
    // Initial state should be STOPPED.
    assertThat(ikePpnStateTracker.getVpnInternalState()).isEqualTo(VpnInternalState.STOPPED);
    assertThat(ikePpnStateTracker.getVpnExternalState()).isEqualTo(VpnExternalState.STOPPED);

    // VPN started.
    ikePpnStateTracker.setStarted(account);
    shadowOf(Looper.getMainLooper()).idle();

    // Verify VPN internal state is PROVISION and external state is DISCONNECTED.
    assertThat(ikePpnStateTracker.getVpnInternalState()).isEqualTo(VpnInternalState.PROVISIONING);
    assertThat(ikePpnStateTracker.getVpnExternalState()).isEqualTo(VpnExternalState.DISCONNECTED);
    verify(mockPpnListener).onPpnStarted(account, true);
    verify(mockPpnListener).onPpnDisconnected(any(PpnDisconnectionStatus.class));

    // VPN provision succeeded.
    ikePpnStateTracker.setProvisioned();
    shadowOf(Looper.getMainLooper()).idle();

    // Verify VPN internal state is CONNECTING and external state is DISCONNECTED.
    assertThat(ikePpnStateTracker.getVpnInternalState()).isEqualTo(VpnInternalState.CONNECTING);
    assertThat(ikePpnStateTracker.getVpnExternalState()).isEqualTo(VpnExternalState.DISCONNECTED);

    // VPN gets connected.
    ikePpnStateTracker.setConnected();
    shadowOf(Looper.getMainLooper()).idle();

    // Verify VPN internal and external states are all CONNECTED.
    assertThat(ikePpnStateTracker.getVpnInternalState()).isEqualTo(VpnInternalState.CONNECTED);
    assertThat(ikePpnStateTracker.getVpnExternalState()).isEqualTo(VpnExternalState.CONNECTED);
    verify(mockPpnListener).onPpnConnected(any(PpnConnectionStatus.class));

    // VPN gets paused.
    ikePpnStateTracker.setPaused();
    shadowOf(Looper.getMainLooper()).idle();

    // Verify VPN internal and external states are all PAUSED.
    assertThat(ikePpnStateTracker.getVpnInternalState()).isEqualTo(VpnInternalState.PAUSED);
    assertThat(ikePpnStateTracker.getVpnExternalState()).isEqualTo(VpnExternalState.PAUSED);
    verify(mockPpnListener).onPpnSnoozed(any(PpnSnoozeStatus.class));

    // VPN gets resumed.
    ikePpnStateTracker.setResumed();
    shadowOf(Looper.getMainLooper()).idle();

    // Verify VPN internal and external states are all DISCONNECTED.
    assertThat(ikePpnStateTracker.getVpnInternalState()).isEqualTo(VpnInternalState.DISCONNECTED);
    assertThat(ikePpnStateTracker.getVpnExternalState()).isEqualTo(VpnExternalState.DISCONNECTED);
    verify(mockPpnListener).onPpnResumed(any(PpnResumeStatus.class));

    // VPN do the provision but failed with transient error.
    ikePpnStateTracker.setProvisionFailed(new PpnStatus(Code.INVALID_ARGUMENT, "Test"), false);
    shadowOf(Looper.getMainLooper()).idle();

    // Verify VPN internal state is WAITING_REPROVISION and external state is DISCONNECTED.
    assertThat(ikePpnStateTracker.getVpnInternalState())
        .isEqualTo(VpnInternalState.WAITING_REPROVISION);
    assertThat(ikePpnStateTracker.getVpnExternalState()).isEqualTo(VpnExternalState.DISCONNECTED);

    // VPN retries the provision but failed with permanent error.
    ikePpnStateTracker.setProvisionFailed(new PpnStatus(Code.INVALID_ARGUMENT, "Test"), true);
    shadowOf(Looper.getMainLooper()).idle();

    // Verify VPN internal state is PROVISION_FAILED and external state is DISCONNECTED.
    assertThat(ikePpnStateTracker.getVpnInternalState())
        .isEqualTo(VpnInternalState.PROVISION_FAILED);
    assertThat(ikePpnStateTracker.getVpnExternalState()).isEqualTo(VpnExternalState.DISCONNECTED);

    // VPN failed because of the permanent provision error.
    ikePpnStateTracker.setFailed();
    shadowOf(Looper.getMainLooper()).idle();

    // Verify VPN internal state is FAILED and external state is DISCONNECTED.
    assertThat(ikePpnStateTracker.getVpnInternalState()).isEqualTo(VpnInternalState.FAILED);
    assertThat(ikePpnStateTracker.getVpnExternalState()).isEqualTo(VpnExternalState.DISCONNECTED);

    // VPN gets stopped.
    ikePpnStateTracker.setStopped(PpnStatus.STATUS_OK);
    shadowOf(Looper.getMainLooper()).idle();

    // Verify VPN internal and external states are all STOPPED.
    assertThat(ikePpnStateTracker.getVpnInternalState()).isEqualTo(VpnInternalState.STOPPED);
    assertThat(ikePpnStateTracker.getVpnExternalState()).isEqualTo(VpnExternalState.STOPPED);
    verify(mockPpnListener).onPpnStopped(any(PpnStatus.class));
  }
}
