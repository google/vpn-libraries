// Copyright 2023 Google LLC
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

package com.google.android.libraries.privacy.ppn.xenon.impl.v2;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import com.google.android.gms.tasks.Task;
import com.google.android.gms.tasks.TaskCompletionSource;
import com.google.android.gms.tasks.Tasks;
import com.google.android.libraries.privacy.ppn.PpnOptions;
import com.google.android.libraries.privacy.ppn.internal.NetworkInfo.AddressFamily;
import com.google.android.libraries.privacy.ppn.internal.http.HttpFetcher;
import com.google.android.libraries.privacy.ppn.xenon.PpnNetwork;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import java.io.IOException;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.SocketException;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

/**
 * PpnNetworkValidator performs network validation by attempting to send an HTTP GET to the
 * ConnectivityCheckUrl set in the PpnOptions.
 */
final class PpnNetworkValidator {
  private static final String TAG = "PpnNetworkValidator";

  private final NetworkValidationListener networkValidationListener;
  private final PpnOptions ppnOptions;
  private final Context context;
  private final HttpFetcher httpFetcher;
  private final Handler mainHandler;
  private final Map<PpnNetwork, Task<Boolean>> networkValidationsMap;

  public interface NetworkValidationListener {
    void validationPassed(PpnNetwork ppnNetwork, AddressFamily addressFamily);
  }

  public PpnNetworkValidator(
      Context context,
      NetworkValidationListener networkValidationListener,
      HttpFetcher httpFetcher,
      PpnOptions ppnOptions) {
    this.context = context;
    this.networkValidationListener = networkValidationListener;
    this.httpFetcher = httpFetcher;
    this.ppnOptions = ppnOptions;
    this.mainHandler = new Handler(Looper.getMainLooper());
    this.networkValidationsMap = new HashMap<>();
  }

  @CanIgnoreReturnValue
  public Task<Boolean> validateNetwork(PpnNetwork ppnNetwork) {
    synchronized (this) {
      Log.w(TAG, String.format("Network validation requested for %s", ppnNetwork));
      if (networkValidationsMap.containsKey(ppnNetwork)) {
        printNetworkValidationStatus(ppnNetwork);
      } else {
        networkValidationsMap.put(ppnNetwork, evaluateNetworkConnectivityAsync(ppnNetwork));
      }
      return networkValidationsMap.get(ppnNetwork);
    }
  }

  private void printNetworkValidationStatus(PpnNetwork ppnNetwork) {
    Task<Boolean> validationTask = networkValidationsMap.get(ppnNetwork);
    if (validationTask.isComplete()) {
      if (validationTask.getResult()) {
        Log.w(TAG, String.format("Network validation already succeeded for %s.", ppnNetwork));
      } else {
        Log.w(TAG, String.format("Network validation already failed for %s.", ppnNetwork));
      }
    } else {
      Log.w(TAG, String.format("Network validation already in progress for %s.", ppnNetwork));
    }
  }

  public void clearNetworkValidation(PpnNetwork ppnNetwork) {
    synchronized (this) {
      Log.w(TAG, String.format("Clearing network validation for %s.", ppnNetwork));
      networkValidationsMap.remove(ppnNetwork);
    }
  }

  public void clearAllNetworkValidation() {
    synchronized (this) {
      Log.w(TAG, "Clearing all network validation info.");
      networkValidationsMap.clear();
    }
  }

  /**
   * Checks if the provided PpnNetwork is still being validated. If it is, verify if the network has
   * connectivity. If so, inform the NetworkValidationListener.
   *
   * @param attemptNum The number of times that validation has been attempted for this network.
   * @return a Task that is resolved as true if the network was validated.
   */
  private Task<Boolean> evaluatePendingNetworkConnectivityAsync(
      PpnNetwork ppnNetwork, int attemptNum) {
    synchronized (this) {
      // The task will not be in the map yet on the first attempt.
      if (attemptNum != 0 && !networkValidationsMap.containsKey(ppnNetwork)) {
        Log.w(TAG, String.format("Network validation cancelled for %s.", ppnNetwork));
        return Tasks.forResult(false);
      }
    }

    Log.w(TAG, String.format("Validating Network: %s", ppnNetwork));

    boolean hasIPv4 = false;
    boolean hasIPv6 = false;
    ConnectivityManager manager = getConnectivityManager();
    LinkProperties linkProperties = manager.getLinkProperties(ppnNetwork.getNetwork());
    if (linkProperties != null) {
      for (LinkAddress linkAddress : linkProperties.getLinkAddresses()) {
        InetAddress address = linkAddress.getAddress();
        if (!isGlobalAddress(address)) {
          continue;
        }
        if (address instanceof Inet4Address) {
          hasIPv4 = true;
        } else if (address instanceof Inet6Address) {
          hasIPv6 = true;
        }
      }
    } else {
      hasIPv4 = true;
      hasIPv6 = true;
    }

    Task<Boolean> ipv4ConnectivityTask;
    if (hasIPv4) {
      ipv4ConnectivityTask = canConnectToInternetAsync(ppnNetwork, AddressFamily.V4);
    } else {
      ipv4ConnectivityTask = Tasks.forResult(false);
    }

    Task<Boolean> ipv6ConnectivityTask;
    if (hasIPv6) {
      ipv6ConnectivityTask = canConnectToInternetAsync(ppnNetwork, AddressFamily.V6);
    } else {
      ipv6ConnectivityTask = Tasks.forResult(false);
    }

    // Check if this PpnNetwork can successfully connect to the internet. There are cases where
    // this does not work due to multiple Cellular networks and dual SIMs, or the Wifi network has
    // a captive portal.
    return Tasks.whenAllComplete(ipv4ConnectivityTask, ipv6ConnectivityTask)
        .continueWithTask(
            (task) -> {
              boolean ipv4Connectivity = false;
              boolean ipv6Connectivity = false;

              if (ipv4ConnectivityTask.isSuccessful()) {
                ipv4Connectivity = ipv4ConnectivityTask.getResult();
              } else {
                Log.w(
                    TAG,
                    String.format(
                        "Network %s encountered exception in IPv4 connectivity check.", ppnNetwork),
                    ipv4ConnectivityTask.getException());
              }
              if (ipv6ConnectivityTask.isSuccessful()) {
                ipv6Connectivity = ipv6ConnectivityTask.getResult();
              } else {
                Log.w(
                    TAG,
                    String.format(
                        "Network %s encountered exception in IPv6 connectivity check.", ppnNetwork),
                    ipv6ConnectivityTask.getException());
              }

              if (!(ipv4Connectivity || ipv6Connectivity)) {
                Log.w(TAG, String.format("Network %s FAILED connectivity check.", ppnNetwork));
                // Try again later
                return recheckConnectivityLaterAsync(ppnNetwork, attemptNum);
              }

              Log.w(TAG, String.format("Network %s PASSES Connectivity check", ppnNetwork));

              AddressFamily addressFamily;
              if (ipv4Connectivity && ipv6Connectivity) {
                addressFamily = AddressFamily.V4V6;
              } else if (ipv4Connectivity) {
                addressFamily = AddressFamily.V4;
              } else {
                addressFamily = AddressFamily.V6;
              }

              synchronized (this) {
                if (!this.networkValidationsMap.containsKey(ppnNetwork)) {
                  Log.w(TAG, String.format("Network validation cancelled for %s.", ppnNetwork));
                  return Tasks.forResult(false);
                }
                Log.w(TAG, String.format("Network validation succeeded for %s.", ppnNetwork));
                this.networkValidationListener.validationPassed(ppnNetwork, addressFamily);
              }

              return Tasks.forResult(true);
            });
  }

  private ConnectivityManager getConnectivityManager() {
    return (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
  }

  private static boolean isGlobalAddress(InetAddress address) {
    return !(address.isLoopbackAddress()
        || address.isMulticastAddress()
        || address.isAnyLocalAddress()
        || (address instanceof Inet6Address
            && (address.isLinkLocalAddress() || address.isSiteLocalAddress())));
  }

  /** Schedules a retry of a network that has failed a connectivity check. */
  private Task<Boolean> recheckConnectivityLaterAsync(PpnNetwork ppnNetwork, int attemptNum) {
    int nextAttemptNum = attemptNum + 1;
    if (nextAttemptNum >= this.ppnOptions.getValidationMaxAttempts()) {
      Log.w(TAG, "Giving up connectivity check retries for " + ppnNetwork);
      return Tasks.forResult(false);
    }

    // Retry with exponential backoff.
    long initialRetryDelayMs = this.ppnOptions.getInitialValidationRetryDelay().toMillis();
    Duration retryDelay = Duration.ofMillis(initialRetryDelayMs * (long) Math.pow(2, attemptNum));
    Log.w(TAG, "Retrying connectivity check for " + ppnNetwork + " in " + retryDelay);

    return delay(retryDelay)
        .continueWithTask(
            (task) -> {
              Log.w(TAG, "Retrying connectivity check for " + ppnNetwork + " now");
              return evaluatePendingNetworkConnectivityAsync(ppnNetwork, nextAttemptNum);
            });
  }

  /** Returns a Task that is resolved after the given duration. */
  private Task<Void> delay(Duration duration) {
    TaskCompletionSource<Void> tcs = new TaskCompletionSource<>();
    mainHandler.postDelayed(() -> tcs.setResult(null), duration.toMillis());
    return tcs.getTask();
  }

  /**
   * Checks whether the PpnNetwork has internet by checking whether we can bind a socket to this
   * PpnNetwork and in the case of Wifi, whether we can establish a quick Url connection.
   */
  private Task<Boolean> canConnectToInternetAsync(
      PpnNetwork ppnNetwork, AddressFamily addressFamily) {
    TaskCompletionSource<Boolean> tcs = new TaskCompletionSource<>();
    ppnOptions
        .getBackgroundExecutor()
        .execute(
            () -> {
              try {
                tcs.setResult(canConnectToInternet(ppnNetwork, addressFamily));
              } finally {
                // This shouldn't happen, but if we somehow have a RuntimeException or missed some
                // case in the code above, this will mark the connectivity check as failed so that
                // it doesn't silently hang forever.
                tcs.trySetException(
                    new IllegalStateException(
                        "Connectivity check failed to complete task. Marking as failed."));
              }
            });
    return tcs.getTask();
  }

  /**
   * Checks whether the PpnNetwork has internet by checking whether we can bind a socket to this
   * PpnNetwork and in the case of Wifi, whether we can establish a quick Url connection.
   */
  private boolean canConnectToInternet(PpnNetwork ppnNetwork, AddressFamily addressFamily) {
    // Try to create a socket.
    DatagramSocket socket;
    try {
      socket = new DatagramSocket();
    } catch (SocketException e) {
      Log.w(
          TAG,
          String.format(
              "Unable to create socket to check whether PpnNetwork %s has Internet.", ppnNetwork),
          e);
      return false;
    }

    // Try to bind that socket to the network.
    try {
      ppnNetwork.getNetwork().bindSocket(socket);
    } catch (IOException e) {
      Log.w(
          TAG,
          String.format(
              "Unable to bind socket to check whether PpnNetwork %s has Internet.", ppnNetwork),
          e);
      return false;
    } finally {
      socket.close();
    }

    // Try a reachability check on the network.
    Log.w(TAG, String.format("Checking connectivity for network %s", ppnNetwork));
    boolean pingSuccessful =
        httpFetcher.checkGet(
            ppnOptions.getConnectivityCheckUrl(), ppnNetwork.getNetwork(), addressFamily);

    if (!pingSuccessful) {
      Log.w(
          TAG,
          String.format(
              "PpnNetwork %s FAILS connectivity check (%s).", ppnNetwork, addressFamily.name()));
      return false;
    }
    Log.w(
        TAG,
        String.format(
            "PpnNetwork %s PASSES connectivity check (%s).", ppnNetwork, addressFamily.name()));

    Log.w(TAG, String.format("PpnNetwork %s CAN connect to Internet.", ppnNetwork));
    return true;
  }

  /**
   * Starts a connectivity check on the network.
   *
   * <p>Returns a Task that is resolved as true if the network was validated.
   */
  private Task<Boolean> evaluateNetworkConnectivityAsync(PpnNetwork ppnNetwork) {
    return evaluatePendingNetworkConnectivityAsync(ppnNetwork, /* attemptNum= */ 0);
  }
}
