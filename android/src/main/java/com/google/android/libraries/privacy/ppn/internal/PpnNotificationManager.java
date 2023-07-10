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

package com.google.android.libraries.privacy.ppn.internal;

import android.app.Notification;
import android.app.Service;
import android.content.Context;
import android.content.pm.ServiceInfo;
import android.os.Build;
import android.os.Build.VERSION;
import android.util.Log;
import androidx.core.app.NotificationManagerCompat;
import javax.annotation.Nullable;

/**
 * Handler of lifecycle events for setting the permanent Notification for the PPN Service. This
 * class is thread-safe.
 */
public class PpnNotificationManager {
  private static final String TAG = "PpnNotificationManager";

  /* A lock guarding all state in this class. */
  private final Object lock = new Object();

  /* The ID to use for showing the Notification in Android. Once set, this should never change. */
  private int notificationId;

  /* The most recent notification set from the client. */
  @Nullable private Notification notification;

  /* If set, then the Notification has been shown for the given Service. */
  @Nullable private Service service = null;

  /** Returns whether a Notification has already been set. */
  public boolean hasNotification() {
    synchronized (lock) {
      return notification != null;
    }
  }

  /**
   * Attaches this notification manager to the given Service, and shows the Notification if it's
   * already been set. Should be called by Service.onCreate().
   */
  public void startService(Service service) {
    synchronized (lock) {
      this.service = service;

      // If the app has already set a notification, use it now.
      if (notification != null) {
        Log.i(TAG, "Permanent notification was set before service started. Showing it now.");
        updateNotification();
      } else {
        Log.i(TAG, "A permanent notification has not been set.");
      }
    }
  }

  /**
   * Resets the Notification state when the Service is stopped. This should be called in
   * Service.onDestroy().
   */
  public void stopService() {
    Log.i(TAG, "Clearing notification because PPN has stopped.");
    synchronized (lock) {
      if (service == null) {
        Log.e(TAG, "stopService() called with null service.");
        return;
      }
      if (VERSION.SDK_INT >= Build.VERSION_CODES.O) {
        service.stopForeground(Service.STOP_FOREGROUND_REMOVE);
      } else {
        NotificationManagerCompat manager = NotificationManagerCompat.from(service);
        manager.cancel(notificationId);
      }
      service = null;
      notification = null;
    }
  }

  /**
   * Sets the permanent Notification to use with the Service. This can be called at any time. If the
   * Service is not yet running, this will save the Notification for later. If the Service is
   * running, this will show or update the Notification.
   *
   * @param id The ID to use for the Notification. Must stay the same for the life of the Service.
   * @param notification The notification to show.
   * @throws IllegalArgumentException if a different ID is used for a single run of the service.
   */
  public void setNotification(Context context, int id, Notification notification) {
    Log.i(TAG, "Setting permanent notification.");
    synchronized (lock) {
      if (this.notification != null && this.notificationId != id) {
        throw new IllegalArgumentException(
            "setNotification was called with id="
                + id
                + ", but previously had id="
                + this.notificationId);
      }

      this.notificationId = id;
      this.notification = notification;

      if (service != null) {
        // The service has already been started, so set the notification.
        Log.i(TAG, "The service is already running. Updating notification.");
        updateNotification();
      }
    }
  }

  /** Attaches the Notification to the service and shows it. */
  private void updateNotification() {
    synchronized (lock) {
      if (VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
        // Including the foregroundServiceType for Android U & above.
        service.startForeground(
            notificationId, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
      } else if (VERSION.SDK_INT >= Build.VERSION_CODES.O) {
        service.startForeground(notificationId, notification);
      } else {
        NotificationManagerCompat manager = NotificationManagerCompat.from(service);
        manager.notify(notificationId, notification);
      }
    }
  }
}
