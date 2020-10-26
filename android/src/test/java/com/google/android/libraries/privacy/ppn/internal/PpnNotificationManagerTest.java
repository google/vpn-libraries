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

package com.google.android.libraries.privacy.ppn.internal;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;
import static org.robolectric.Shadows.shadowOf;

import android.app.Notification;
import android.app.Service;
import android.content.Context;
import android.net.VpnService;
import androidx.test.core.app.ApplicationProvider;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;
import org.robolectric.Robolectric;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.shadows.ShadowService;

@RunWith(RobolectricTestRunner.class)
public class PpnNotificationManagerTest {
  private static final int NOTIFICATION_ID = 1;

  private Service service;
  private ShadowService shadowService;

  @Mock private Notification mockNotification;
  @Mock private Notification mockOtherNotification;
  @Rule public final MockitoRule mockito = MockitoJUnit.rule();

  @Before
  public void setUp() {
    service = Robolectric.buildService(VpnService.class).get();
    shadowService = shadowOf(service);
  }

  @Test
  public void testManualStart() {
    Context context = ApplicationProvider.getApplicationContext();
    PpnNotificationManager manager = new PpnNotificationManager();
    assertThat(manager.hasNotification()).isFalse();

    manager.setNotification(context, NOTIFICATION_ID, mockNotification);
    manager.startService(service);

    assertThat(manager.hasNotification()).isTrue();
    assertThat(shadowService.isLastForegroundNotificationAttached()).isTrue();
    assertThat(shadowService.getLastForegroundNotification()).isSameInstanceAs(mockNotification);
    assertThat(shadowService.getLastForegroundNotificationId()).isEqualTo(NOTIFICATION_ID);
  }

  @Test
  public void testAutoStart() {
    Context context = ApplicationProvider.getApplicationContext();
    PpnNotificationManager manager = new PpnNotificationManager();
    assertThat(manager.hasNotification()).isFalse();

    // The Service starts first.
    manager.startService(service);

    // Verify the notification hasn't been set yet.
    assertThat(manager.hasNotification()).isFalse();
    assertThat(shadowService.isLastForegroundNotificationAttached()).isFalse();

    // The client calls setNotification.
    manager.setNotification(context, NOTIFICATION_ID, mockNotification);

    // Verify that the notification is now set.
    assertThat(manager.hasNotification()).isTrue();
    assertThat(shadowService.isLastForegroundNotificationAttached()).isTrue();
    assertThat(shadowService.getLastForegroundNotification()).isSameInstanceAs(mockNotification);
    assertThat(shadowService.getLastForegroundNotificationId()).isEqualTo(NOTIFICATION_ID);
  }

  @Test
  public void testClearNotification() {
    Context context = ApplicationProvider.getApplicationContext();
    PpnNotificationManager manager = new PpnNotificationManager();
    assertThat(manager.hasNotification()).isFalse();

    // Start the service.
    manager.setNotification(context, NOTIFICATION_ID, mockNotification);
    manager.startService(service);
    assertThat(manager.hasNotification()).isTrue();
    assertThat(shadowService.isLastForegroundNotificationAttached()).isTrue();
    assertThat(shadowService.getLastForegroundNotification()).isSameInstanceAs(mockNotification);
    assertThat(shadowService.getLastForegroundNotificationId()).isEqualTo(NOTIFICATION_ID);

    // Stop the service.
    manager.stopService();
    assertThat(manager.hasNotification()).isFalse();
    assertThat(shadowService.isLastForegroundNotificationAttached()).isFalse();

    // Start the service again.
    manager.setNotification(context, NOTIFICATION_ID, mockOtherNotification);
    manager.startService(service);
    assertThat(manager.hasNotification()).isTrue();
    assertThat(shadowService.isLastForegroundNotificationAttached()).isTrue();
    assertThat(shadowService.getLastForegroundNotification())
        .isSameInstanceAs(mockOtherNotification);
    assertThat(shadowService.getLastForegroundNotificationId()).isEqualTo(NOTIFICATION_ID);
  }

  @Test
  public void testChangeNotificationBeforeStart() {
    Context context = ApplicationProvider.getApplicationContext();
    PpnNotificationManager manager = new PpnNotificationManager();
    assertThat(manager.hasNotification()).isFalse();

    manager.setNotification(context, NOTIFICATION_ID, mockNotification);
    manager.setNotification(context, NOTIFICATION_ID, mockOtherNotification);
    manager.startService(service);

    assertThat(manager.hasNotification()).isTrue();
    assertThat(shadowService.isLastForegroundNotificationAttached()).isTrue();
    assertThat(shadowService.getLastForegroundNotification())
        .isSameInstanceAs(mockOtherNotification);
    assertThat(shadowService.getLastForegroundNotificationId()).isEqualTo(NOTIFICATION_ID);
  }

  @Test
  public void testChangeNotificationAfterStart() {
    Context context = ApplicationProvider.getApplicationContext();
    PpnNotificationManager manager = new PpnNotificationManager();
    assertThat(manager.hasNotification()).isFalse();

    // Start the service with one notification.
    manager.setNotification(context, NOTIFICATION_ID, mockNotification);
    manager.startService(service);

    // Change it to a different notification.
    manager.setNotification(context, NOTIFICATION_ID, mockOtherNotification);

    // Verify that it got changed.
    assertThat(manager.hasNotification()).isTrue();
    assertThat(shadowService.isLastForegroundNotificationAttached()).isTrue();
    assertThat(shadowService.getLastForegroundNotification())
        .isSameInstanceAs(mockOtherNotification);
    assertThat(shadowService.getLastForegroundNotificationId()).isEqualTo(NOTIFICATION_ID);
  }

  @Test
  public void testStopBeforeSet() {
    PpnNotificationManager manager = new PpnNotificationManager();
    assertThat(manager.hasNotification()).isFalse();

    // The Service starts first.
    manager.startService(service);

    // Verify the notification hasn't been set yet.
    assertThat(manager.hasNotification()).isFalse();
    assertThat(shadowService.isLastForegroundNotificationAttached()).isFalse();

    // Stop the Service instead of calling setNotification().
    manager.stopService();

    // Verify the notification still hasn't been set.
    assertThat(manager.hasNotification()).isFalse();
    assertThat(shadowService.isLastForegroundNotificationAttached()).isFalse();
  }

  @Test
  public void testChangingId() {
    Context context = ApplicationProvider.getApplicationContext();
    PpnNotificationManager manager = new PpnNotificationManager();
    assertThat(manager.hasNotification()).isFalse();

    // Start the service with one notification.
    manager.setNotification(context, NOTIFICATION_ID, mockNotification);
    manager.startService(service);

    // Try to change it to a different notification with a different ID.
    assertThrows(
        IllegalArgumentException.class,
        () -> manager.setNotification(context, NOTIFICATION_ID + 1, mockOtherNotification));

    // Verify that it didn't change.
    assertThat(manager.hasNotification()).isTrue();
    assertThat(shadowService.isLastForegroundNotificationAttached()).isTrue();
    assertThat(shadowService.getLastForegroundNotification()).isSameInstanceAs(mockNotification);
    assertThat(shadowService.getLastForegroundNotificationId()).isEqualTo(NOTIFICATION_ID);
  }
}
