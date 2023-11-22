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
import java.util.Optional;

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
  private final Map<PpnNetwork, Boolean> networkValidationsMap;

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
      if (!networkValidationsMap.containsKey(ppnNetwork)) {
        networkValidationsMap.put(ppnNetwork, false);
      }
      return evaluateNetworkConnectivityAsync(ppnNetwork);
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
   * @param retries The number of times to retry if the connection fails. For example, if this is
   *     zero, the connection will only be attempted once.
   * @return a Task that is resolved as true if the network was validated.
   */
  private Task<Boolean> evaluatePendingNetworkConnectivityAsync(
      PpnNetwork ppnNetwork, int retries) {
    synchronized (this) {
      Optional<Task<Boolean>> validatedOrCancelled = checkIfValidatedOrCancelled(ppnNetwork);
      if (validatedOrCancelled.isPresent()) {
        return validatedOrCancelled.get();
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
                return recheckConnectivityLaterAsync(ppnNetwork, retries);
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
                Optional<Task<Boolean>> validatedOrCancelled =
                    checkIfValidatedOrCancelled(ppnNetwork);
                if (validatedOrCancelled.isPresent()) {
                  return validatedOrCancelled.get();
                }
                Log.w(
                    TAG,
                    String.format(
                        "Network %s validated. Canceling remaining connectivity checks.",
                        ppnNetwork));
                this.networkValidationsMap.put(ppnNetwork, true);
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

  private Optional<Task<Boolean>> checkIfValidatedOrCancelled(PpnNetwork ppnNetwork) {
    Boolean validated = networkValidationsMap.get(ppnNetwork);
    if (validated == null) {
      Log.w(TAG, String.format("Network validation cancelled for %s.", ppnNetwork));
      return Optional.of(Tasks.forResult(false));
    }
    if (validated) {
      Log.w(TAG, String.format("Network %s already validated.", ppnNetwork));
      return Optional.of(Tasks.forResult(true));
    }
    return Optional.empty();
  }

  /** Schedules a retry of a network that has failed a connectivity check. */
  private Task<Boolean> recheckConnectivityLaterAsync(PpnNetwork ppnNetwork, int retries) {
    if (retries <= 0) {
      Log.w(TAG, "Giving up connectivity check retries for " + ppnNetwork);
      return Tasks.forResult(false);
    }

    Log.w(
        TAG,
        "Retrying connectivity check for "
            + ppnNetwork
            + " in "
            + ppnOptions.getConnectivityCheckRetryDelay());

    return delay(ppnOptions.getConnectivityCheckRetryDelay())
        .continueWithTask(
            (task) -> {
              Log.w(TAG, "Retrying connectivity check for " + ppnNetwork + " now");
              return evaluatePendingNetworkConnectivityAsync(ppnNetwork, retries - 1);
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
    return evaluatePendingNetworkConnectivityAsync(
        ppnNetwork, ppnOptions.getConnectivityCheckMaxRetries());
  }
}
