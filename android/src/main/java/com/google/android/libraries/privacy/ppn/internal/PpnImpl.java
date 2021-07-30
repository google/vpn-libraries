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

import static com.google.android.libraries.privacy.ppn.internal.http.HttpFetcher.DNS_CACHE_TIMEOUT;
import static com.google.android.libraries.privacy.ppn.internal.http.HttpFetcher.DNS_LOOKUP_TIMEOUT;

import android.accounts.Account;
import android.app.Notification;
import android.content.Context;
import android.content.Intent;
import android.net.Network;
import android.net.VpnService;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import androidx.annotation.Nullable;
import androidx.annotation.VisibleForTesting;
import androidx.work.WorkManager;
import com.google.android.gms.tasks.Task;
import com.google.android.gms.tasks.TaskCompletionSource;
import com.google.android.gms.tasks.TaskExecutors;
import com.google.android.gms.tasks.Tasks;
import com.google.android.libraries.privacy.ppn.Ppn;
import com.google.android.libraries.privacy.ppn.PpnAccountManager;
import com.google.android.libraries.privacy.ppn.PpnAccountRefresher;
import com.google.android.libraries.privacy.ppn.PpnConnectingStatus;
import com.google.android.libraries.privacy.ppn.PpnConnectionStatus;
import com.google.android.libraries.privacy.ppn.PpnDisconnectionStatus;
import com.google.android.libraries.privacy.ppn.PpnException;
import com.google.android.libraries.privacy.ppn.PpnListener;
import com.google.android.libraries.privacy.ppn.PpnOptions;
import com.google.android.libraries.privacy.ppn.PpnReconnectionStatus;
import com.google.android.libraries.privacy.ppn.PpnResumeStatus;
import com.google.android.libraries.privacy.ppn.PpnSnoozeStatus;
import com.google.android.libraries.privacy.ppn.PpnStatus;
import com.google.android.libraries.privacy.ppn.PpnStatus.Code;
import com.google.android.libraries.privacy.ppn.PpnTelemetry;
import com.google.android.libraries.privacy.ppn.internal.http.CachedDns;
import com.google.android.libraries.privacy.ppn.internal.http.Dns;
import com.google.android.libraries.privacy.ppn.internal.http.HttpFetcher;
import com.google.android.libraries.privacy.ppn.internal.service.PpnServiceDebugJson;
import com.google.android.libraries.privacy.ppn.internal.service.ProtectedSocketFactoryFactory;
import com.google.android.libraries.privacy.ppn.internal.service.VpnBypassDns;
import com.google.android.libraries.privacy.ppn.internal.service.VpnManager;
import com.google.android.libraries.privacy.ppn.krypton.Krypton;
import com.google.android.libraries.privacy.ppn.krypton.KryptonException;
import com.google.android.libraries.privacy.ppn.krypton.KryptonFactory;
import com.google.android.libraries.privacy.ppn.krypton.KryptonImpl;
import com.google.android.libraries.privacy.ppn.krypton.KryptonIpSecHelper;
import com.google.android.libraries.privacy.ppn.krypton.KryptonIpSecHelperImpl;
import com.google.android.libraries.privacy.ppn.krypton.KryptonListener;
import com.google.android.libraries.privacy.ppn.xenon.PpnNetwork;
import com.google.android.libraries.privacy.ppn.xenon.PpnNetworkListener;
import com.google.android.libraries.privacy.ppn.xenon.Xenon;
import com.google.android.libraries.privacy.ppn.xenon.impl.XenonImpl;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListenableFuture;
import java.time.Duration;
import java.util.Collections;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import org.json.JSONObject;

/** A PPN implementation built on top of GCS. */
public class PpnImpl implements Ppn, KryptonListener, PpnNetworkListener {
  private static final String TAG = "PpnImpl";

  // By default, keep the Krypton stopped status as "unknown" when Krypton is running, since the
  // default value will only be used if the Service is somehow stopped without the VPN first being
  // revoked or stopped by Krypton.
  private static final PpnStatus KRYPTON_STOPPED_STATUS_UNKNOWN =
      new PpnStatus(Code.UNKNOWN, "Service was stopped while Krypton was still running.");

  private final Context context;

  /* Executor for any work that PPN needs to do off the UI thread. */
  private final ExecutorService backgroundExecutor;

  private final VpnManager vpnManager;
  private final HttpFetcher httpFetcher;
  private final PpnNotificationManager notificationManager;
  private final PpnAccountManager accountManager;
  private PpnTelemetryManager telemetry;

  private final PpnOptions options;
  /* This field is null until it is needed, so that this can be constructed on the UI thread. */
  @Nullable private PpnSettings settings;
  private final Object settingsLock = new Object();

  @Nullable private PpnListener listener;
  private final Handler mainHandler = new Handler(Looper.getMainLooper());

  @Nullable private Krypton krypton;
  private final Object kryptonLock = new Object();
  private KryptonFactory kryptonFactory;
  private PpnStatus kryptonStoppedStatus = KRYPTON_STOPPED_STATUS_UNKNOWN;

  private Xenon xenon;

  // This is lazy-initialized, because it is only created if we are actually using IpSec.
  @Nullable private KryptonIpSecHelper ipSecHelper;

  // These settings can be changed while PPN is running.
  private boolean safeDisconnectEnabled;
  private Set<String> disallowedApplications = Collections.emptySet();

  // Tracks whether PPN is fully connected, for managing notification state.
  private AtomicBoolean connected = new AtomicBoolean();

  /*
   * Cached account that was used to enable PPN.
   * This is volatile because it is updated from a background thread.
   */
  private volatile Account cachedAccount = null;

  /*
   * Class that refreshes a user account in the background periodically to keep it cached.
   * This is nullable because it's constructed when PPN gets a user account.
   */
  @Nullable private PpnAccountRefresher accountRefresher;

  // TODO: Re-organize these methods so this class is more readable.

  @Override
  public void onKryptonPermanentFailure(PpnStatus status) {
    Log.w(TAG, "Krypton stopped with status: " + status);
    connected.set(false);
    stopKryptonAndService(status);
  }

  @Override
  public void onKryptonCrashed() {
    Log.e(TAG, "Krypton has crashed.");
    Log.e(TAG, "Clearing notification before pending crash.");
    notificationManager.stopService();
  }

  @Override
  public void onKryptonConnected(ConnectionStatus status) {
    Log.w(TAG, "Krypton connected.");
    telemetry.notifyConnected();
    if (listener == null) {
      return;
    }
    try {
      PpnConnectionStatus ppnStatus = PpnConnectionStatus.fromProto(status);
      // The Krypton listener doesn't guarantee calls are on the main thread, so enforce it for PPN.
      mainHandler.post(() -> listener.onPpnConnected(ppnStatus));
    } catch (PpnException e) {
      Log.e(TAG, "Invalid status proto.", e);
    }
    connected.set(true);
  }

  @Override
  public void onKryptonConnecting(ConnectingStatus status) {
    Log.w(TAG, "Krypton connecting...");
    PpnConnectingStatus connectingStatus = PpnConnectingStatus.fromProto(status);
    Log.w(TAG, "Krypton connecting status: " + connectingStatus);
    if (listener == null) {
      return;
    }

    // The Krypton listener doesn't guarantee calls are on the main thread, so enforce it for PPN.
    mainHandler.post(() -> listener.onPpnConnecting(connectingStatus));
  }

  @Override
  public void onKryptonControlPlaneConnected() {
    Log.w(TAG, "Krypton control plane connected.");
  }

  @Override
  public void onKryptonStatusUpdated(ConnectionStatus status) {
    Log.w(TAG, "Krypton status updated.");
    if (listener == null) {
      return;
    }
    if (!connected.get()) {
      Log.w(TAG, "Ignoring connection status update, because Krypton is disconnected.");
      return;
    }
    try {
      PpnConnectionStatus ppnStatus = PpnConnectionStatus.fromProto(status);
      Log.w(TAG, "Krypton status: " + ppnStatus);
      // The Krypton listener doesn't guarantee calls are on the main thread, so enforce it for PPN.
      mainHandler.post(() -> listener.onPpnStatusUpdated(ppnStatus));
    } catch (PpnException e) {
      Log.e(TAG, "Invalid status proto.", e);
    }
  }

  @Override
  public void onKryptonDisconnected(DisconnectionStatus status) {
    Log.w(TAG, "Krypton disconnected: " + status.getCode() + ": " + status.getMessage());
    telemetry.notifyDisconnected();
    connected.set(false);

    PpnDisconnectionStatus ppnStatus = PpnDisconnectionStatus.fromProto(status);
    Log.w(TAG, "Krypton disconnection status: " + ppnStatus);
    if (listener == null) {
      return;
    }

    // The Krypton listener doesn't guarantee calls are on the main thread, so enforce it for PPN.
    mainHandler.post(() -> listener.onPpnDisconnected(ppnStatus));
  }

  @Override
  public void onKryptonNetworkFailed(PpnStatus status, NetworkInfo networkInfo) {
    Log.w(TAG, "Krypton network " + networkInfo.getNetworkId() + " failed: " + status);
    xenon.deprioritize(networkInfo);
  }

  @Override
  public void onKryptonWaitingToReconnect(ReconnectionStatus status) {
    Log.w(TAG, "Krypton waiting to reconnect...");
    PpnReconnectionStatus reconnectionStatus = PpnReconnectionStatus.fromProto(status);
    Log.w(TAG, "Krypton reconnection status: " + reconnectionStatus);
    if (listener == null) {
      return;
    }

    // The Krypton listener doesn't guarantee calls are on the main thread, so enforce it for PPN.
    mainHandler.post(() -> listener.onPpnWaitingToReconnect(reconnectionStatus));
  }

  @Override
  public void onKryptonSnoozed(SnoozeStatus status) {
    Log.w(TAG, "Krypton is snoozed.");
    Log.w(TAG, "Stopping Xenon for snooze.");
    try {
      xenon.stop();
      Log.w(TAG, "Stopped Xenon for snooze.");
    } catch (PpnException e) {
      Log.e(TAG, "Unable to stop Krypton after PPN is snoozed.", e);
    }
    // TODO: pause AccountRefresher while Krypton is snoozed.
    PpnSnoozeStatus snoozeStatus = PpnSnoozeStatus.fromProto(status);
    Log.w(TAG, "Krypton snooze status: " + snoozeStatus);
    if (listener == null) {
      return;
    }

    // The Krypton listener doesn't guarantee calls are on the main thread, so enforce it for PPN.
    mainHandler.post(() -> listener.onPpnSnoozed(snoozeStatus));
  }

  @Override
  public void onKryptonResumed(ResumeStatus status) {
    Log.w(TAG, "Krypton is resumed.");
    PpnResumeStatus resumeStatus = PpnResumeStatus.fromProto(status);
    Log.w(TAG, "Krypton resume status: " + resumeStatus);
    if (listener == null) {
      return;
    }
    Log.w(TAG, "Starting Xenon after resuming from snooze.");
    try {
      xenon.start();
      Log.w(TAG, "Started Xenon after resuming from snooze.");
    } catch (PpnException e) {
      Log.e(TAG, "Unable to start Krypton after Ppn has resumed.", e);
    }

    // The Krypton listener doesn't guarantee calls are on the main thread, so enforce it for PPN.
    mainHandler.post(() -> listener.onPpnResumed(resumeStatus));
  }

  @Override
  public int onKryptonNeedsTunFd(TunFdData tunFdData) throws PpnException {
    Log.w(TAG, "Krypton requesting TUN fd.");
    int createTunFdResult = vpnManager.createTunFd(tunFdData);
    return createTunFdResult;
  }

  @Override
  public int onKryptonNeedsNetworkFd(NetworkInfo network) throws PpnException {
    Log.w(TAG, "Krypton requesting network fd.");
    PpnNetwork ppnNetwork = xenon.getNetwork(network.getNetworkId());
    if (ppnNetwork == null) {
      throw new PpnException("Unable to find network with id " + network.getNetworkId());
    }
    return vpnManager.createProtectedDatagramSocket(ppnNetwork);
  }

  @Override
  public void onKryptonNeedsIpSecConfiguration(IpSecTransformParams params) throws PpnException {
    synchronized (kryptonLock) {
      if (ipSecHelper == null) {
        ipSecHelper = new KryptonIpSecHelperImpl(context, xenon);
      }
    }
    try {
      ipSecHelper.transformFd(params);
    } catch (KryptonException e) {
      throw new PpnException("Unable to configure IpSec.", e);
    }
  }

  @Override
  public String onKryptonNeedsOAuthToken() throws PpnException {
    return getZincOAuthToken();
  }

  /** Creates a new instance of the PPN. */
  public PpnImpl(Context context, PpnOptions options) {
    this.context = context.getApplicationContext();
    this.options = options;
    this.backgroundExecutor = options.getBackgroundExecutor();
    this.notificationManager = new PpnNotificationManager();
    this.telemetry = new PpnTelemetryManager();
    this.vpnManager = new VpnManager(context);

    Dns dns = new VpnBypassDns(vpnManager);
    if (options.isDnsCacheEnabled()) {
      dns = new CachedDns(dns, DNS_CACHE_TIMEOUT, DNS_LOOKUP_TIMEOUT, backgroundExecutor);
    }
    this.httpFetcher = new HttpFetcher(new ProtectedSocketFactoryFactory(vpnManager), dns);

    this.kryptonFactory =
        (KryptonListener kryptonListener, ExecutorService bgExecutor) ->
            new KryptonImpl(context, httpFetcher, kryptonListener, bgExecutor);

    Optional<PpnAccountManager> accountManager = options.getAccountManager();
    this.accountManager =
        accountManager.isPresent() ? accountManager.get() : new GoogleAccountManager();

    this.xenon = new XenonImpl(context, this, httpFetcher, options);

    this.safeDisconnectEnabled = options.isSafeDisconnectEnabled();
    this.disallowedApplications = options.getDisallowedApplications();

    PpnLibrary.init(this);
  }

  /** Nullifies the cached account used for enabling PPN. */
  @VisibleForTesting
  void clearCachedAccount() {
    Log.i(TAG, "Clearing cached account.");
    cachedAccount = null;
  }

  @Override
  public void start(Account account) throws PpnException {
    Log.w(TAG, "PPN status: " + getDebugJson());
    getSettings().setAccountName(account.name);
    cachedAccount = account;
    // Snapshot the disallowed applications, so that it only changes when PPN is restarted.
    vpnManager.setDisallowedApplications(disallowedApplications);
    startVpn();
  }

  @Override
  public void stop() {
    // Stopping Krypton requires getting the Krypton lock and waiting for Krypton's threads to be
    // joined, so we kick it off to the background Executor.
    backgroundExecutor.execute(() -> stopKryptonAndService(PpnStatus.STATUS_OK));
  }

  @Override
  public ListenableFuture<Void> restart() {
    Log.w(TAG, "Restarting Ppn.");
    return Futures.submit(
        () -> {
          try {
            synchronized (kryptonLock) {
              if (krypton != null) {
                stopKrypton();
                vpnManager.setDisallowedApplications(disallowedApplications);
                startKrypton();
              }
            }
          } catch (PpnException e) {
            Log.e(TAG, "Failed to restart Ppn.", e);
            throw e;
          }
          return null;
        },
        backgroundExecutor);
  }

  @Override
  public ListenableFuture<Void> snooze(Duration snoozeDuration) {
    return Futures.submit(
        () -> {
          try {
            synchronized (kryptonLock) {
              if (krypton != null) {
                Log.i(TAG, "Snoozing krypton connection for " + snoozeDuration.toMillis() + " ms.");
                krypton.snooze(snoozeDuration.toMillis());
              }
            }
          } catch (KryptonException e) {
            Log.e(TAG, "Failed to snooze Ppn for specified duration.", e);
            throw e;
          }
          return null;
        },
        backgroundExecutor);
  }

  @Override
  public ListenableFuture<Void> resume() {
    return Futures.submit(
        () -> {
          try {
            synchronized (kryptonLock) {
              if (krypton != null) {
                Log.i(TAG, "Resuming krypton connection.");
                krypton.resume();
              }
            }
          } catch (KryptonException e) {
            Log.e(TAG, "Failed to resume Ppn after snooze.", e);
            throw e;
          }
          return null;
        },
        backgroundExecutor);
  }

  @Override
  public ListenableFuture<Void> extendSnooze(Duration extendDuration) {
    return Futures.submit(
        () -> {
          try {
            synchronized (kryptonLock) {
              if (krypton != null) {
                Log.i(TAG, "Extending krypton snooze for " + extendDuration.toMillis() + " ms.");
                krypton.extendSnooze(extendDuration.toMillis());
              }
            }
          } catch (KryptonException e) {
            Log.e(
                TAG,
                "Failed to extend snooze duration for " + extendDuration.toMillis() + " ms",
                e);
            throw e;
          }
          return null;
        },
        backgroundExecutor);
  }

  /**
   * Stops Krypton and tells the VpnService to stop.
   *
   * @param status The status that PPN should report to the listener when it is finished stopping.
   */
  @VisibleForTesting
  void stopKryptonAndService(PpnStatus status) {
    Log.w(TAG, "Stopping PPN: " + status);
    try {
      // We have to stop Krypton before trying to stop the Service, because as long as the VPN is
      // established, the Service will be bound by Android as a foreground Service, and stopSelf
      // will be ignored.
      //
      // However, anything other than Krypton that needs to be stopped can be handled by the
      // Service's onDestroy method calling onStopService().
      //
      Log.w(TAG, "Ready to stop Krypton.");
      stopKrypton();
    } catch (PpnException e) {
      Log.e(TAG, "Unable to stop krypton.", e);
    } finally {
      Log.w(TAG, "PPN stopping VpnService.");
      kryptonStoppedStatus = status;
      vpnManager.stopService();
    }
  }

  @Override
  public ListenableFuture<Void> setSafeDisconnectEnabled(boolean enable) {
    // Store the value for the next time PPN is started.
    this.safeDisconnectEnabled = enable;

    // If PPN is already running, tell Krypton to update the value.
    return Futures.submit(
        () -> {
          try {
            synchronized (kryptonLock) {
              if (krypton != null) {
                // Call a setter that injects feature state into Krypton.
                krypton.setSafeDisconnectEnabled(enable);
              }
              // If Krypton isn't running, feature state will be passed on Krypton startup through
              // config.
            }
          } catch (KryptonException e) {
            Log.e(TAG, "Unable to set Safe Disconnect in Krypton.", e);
          }
        },
        backgroundExecutor);
  }

  @Override
  public void setDisallowedApplications(Iterable<String> disallowedApplications) {
    HashSet<String> copy = new HashSet<>();
    for (String packageName : disallowedApplications) {
      copy.add(packageName);
    }
    this.disallowedApplications = Collections.unmodifiableSet(copy);
  }

  /** Returns the current Safe Disconnect state. */
  @Override
  public boolean isSafeDisconnectEnabled() {
    return safeDisconnectEnabled;
  }

  @Override
  public boolean isRunning() {
    return vpnManager.isRunning();
  }

  /** Puts Krypton in a horrible wedged state, for testing app bypass, etc. */
  @Override
  public ListenableFuture<Void> setSimulatedNetworkFailure(boolean simulatedNetworkFailure) {
    return Futures.submit(
        () -> {
          try {
            synchronized (kryptonLock) {
              if (krypton != null) {
                Log.i(TAG, "Setting simulated network failure to " + simulatedNetworkFailure);
                krypton.setSimulatedNetworkFailure(simulatedNetworkFailure);
              } else {
                Log.i(
                    TAG,
                    "Not setting simulated network failure to "
                        + simulatedNetworkFailure
                        + ", because Krypton isn't running.");
              }
            }
          } catch (KryptonException e) {
            Log.e(TAG, "Failed to set simulated network failure.", e);
            throw new PpnException("Failed to set simulated network failure", e);
          }
          return null;
        },
        backgroundExecutor);
  }

  @Override
  public JSONObject getDebugJson() {
    PpnDebugJson.Builder builder = new PpnDebugJson.Builder();

    builder.setServiceDebugJson(new PpnServiceDebugJson.Builder().setRunning(isRunning()).build());

    synchronized (kryptonLock) {
      if (krypton != null) {
        try {
          builder.setKryptonDebugJson(krypton.getDebugJson());
        } catch (KryptonException e) {
          Log.e(TAG, "Unable to get krypton debug json.", e);
        }
      }
    }

    builder.setXenonDebugJson(xenon.getDebugJson());

    return builder.build();
  }

  @Override
  public void setPpnListener(PpnListener listener) {
    this.listener = listener;
  }

  @VisibleForTesting
  void setTelemetryManager(PpnTelemetryManager telemetryManager) {
    telemetry = telemetryManager;
  }

  @Override
  public PpnTelemetry collectTelemetry() {
    logDebugInfoAsync(Duration.ofSeconds(30));
    synchronized (kryptonLock) {
      return telemetry.collect(krypton);
    }
  }

  @Override
  public void setNotification(int notificationId, Notification notification) {
    notificationManager.setNotification(context, notificationId, notification);
  }

  private PpnSettings getSettings() {
    synchronized (settingsLock) {
      if (settings == null) {
        settings = new PpnSettings(context.getApplicationContext());
      }
      return settings;
    }
  }

  private void startVpn() throws PpnException {
    Intent intent = new Intent(VpnService.SERVICE_INTERFACE);
    intent.setPackage(context.getApplicationContext().getPackageName());

    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
      context.startForegroundService(intent);
    } else {
      context.startService(intent);
    }
  }

  /**
   * Handles any PPN logic that needs to occur when the Service is started, such as permanent
   * notification management.
   *
   * @return a Task that will be resolved once all of the async startup work is complete.
   */
  public Task<Void> onStartService(VpnService service) {
    Log.w(TAG, "PPN Service is starting.");

    kryptonStoppedStatus = KRYPTON_STOPPED_STATUS_UNKNOWN;
    vpnManager.setService(service);

    notificationManager.startService(service);

    // Look up the user account and notify the app that the PPN service has started.
    return getPpnAccountAsync()
        .continueWithTask(
            backgroundExecutor,
            accountTask -> {
              Log.w(TAG, "Starting PpnAccountRefresher.");
              accountRefresher =
                  accountManager.createAccountRefresher(
                      WorkManager.getInstance(context.getApplicationContext()),
                      backgroundExecutor,
                      accountTask.getResult().name,
                      options.getZincOAuthScopes());
              accountRefresher.start();

              Log.w(TAG, "PPN ready to start Krypton.");
              startKrypton();
              return accountTask;
            })
        .continueWith(
            TaskExecutors.MAIN_THREAD,
            accountTask -> {
              telemetry.notifyStarted();
              Log.w(TAG, "PPN sending started event.");
              // Notify the app that PPN is started for this user.
              Account account = accountTask.getResult();
              boolean needsNotification = !notificationManager.hasNotification();
              if (listener != null) {
                listener.onPpnStarted(account, needsNotification);
              }
              return null;
            })
        .continueWith(
            TaskExecutors.MAIN_THREAD,
            task -> {
              if (!task.isSuccessful()) {
                // Log the exception here, since non-test callers aren't expected to use the Task.
                Log.e(TAG, "Error starting PPN.", task.getException());
              }
              return null;
            });
  }

  /**
   * Looks up the Account that was used to enable PPN.
   *
   * <p>If PPN has not been enabled with an account, then the return Task will be rejected with a
   * PpnException.
   *
   * @return a Task that will be resolved with the account.
   */
  private Task<Account> getPpnAccountAsync() {
    // If it's cached, just use that.
    if (cachedAccount != null) {
      return Tasks.forResult(cachedAccount);
    }

    // Do any remaining work off of the UI thread.
    TaskCompletionSource<Account> tcs = new TaskCompletionSource<>();
    backgroundExecutor.execute(
        () -> {
          try {
            tcs.trySetResult(getPpnAccount());
          } catch (Exception e) {
            tcs.trySetException(e);
          }
        });
    return tcs.getTask();
  }

  /**
   * Looks up the Account that was used to enable PPN. This should not be called from the UI thread.
   *
   * @throws PpnException if PPN has not been enabled with an account.
   */
  private Account getPpnAccount() throws PpnException {
    Log.w(TAG, "PPN getting Account.");
    ensureBackgroundThread();
    // Look up the Account used for starting PPN.
    String accountName = getSettings().getAccountName();
    if (isNullOrEmpty(accountName)) {
      throw new PpnException("PPN was started without a user account.");
    }
    Account account = accountManager.getAccount(context, accountName);
    Log.w(TAG, "PPN has Account.");
    cachedAccount = account;
    return account;
  }

  /**
   * Fetches a new oauth token for Zinc, using the user who started PPN. This method should not be
   * called from the UI thread.
   *
   * @throws PpnException if no user is available, or the request fails for any reason.
   */
  public String getZincOAuthToken() throws PpnException {
    ensureBackgroundThread();
    Network network = null;
    PpnNetwork ppnNetwork = vpnManager.getNetwork();
    if (ppnNetwork != null) {
      network = ppnNetwork.getNetwork();
    }
    if (accountRefresher == null) {
      throw new PpnException("Tried to getZincOAuthToken with null accountRefresher.");
    }
    return accountRefresher.getToken(context, network);
  }

  /**
   * Returns whether the underlying VpnService should set the STICKY bit to be restarted by Android.
   */
  public boolean isStickyService() {
    return options.isStickyService();
  }

  /** Changes the factory used to create Krypton instances. For testing only. */
  @VisibleForTesting
  void setKryptonFactory(KryptonFactory factory) {
    this.kryptonFactory = factory;
  }

  /** Returns VpnManager for testing only. */
  @VisibleForTesting
  VpnManager getVpnManager() {
    return vpnManager;
  }

  /** Changes the Xenon instance used. For testing only. */
  @VisibleForTesting
  void setXenon(Xenon xenon) {
    this.xenon = xenon;
  }

  /** Creates a KryptonConfig.Builder using the provided options. */
  @VisibleForTesting
  static KryptonConfig.Builder createKryptonConfigBuilder(PpnOptions options) {
    ReconnectorConfig.Builder reconnectorBuilder = ReconnectorConfig.newBuilder();
    if (options.getReconnectorInitialTimeToReconnect().isPresent()) {
      reconnectorBuilder.setInitialTimeToReconnectMsec(
          (int) options.getReconnectorInitialTimeToReconnect().get().toMillis());
    }
    if (options.getReconnectorSessionConnectionDeadline().isPresent()) {
      reconnectorBuilder.setSessionConnectionDeadlineMsec(
          (int) options.getReconnectorSessionConnectionDeadline().get().toMillis());
    }
    ReconnectorConfig reconnectorConfig = reconnectorBuilder.build();

    KryptonConfig.Builder builder =
        KryptonConfig.newBuilder()
            .setZincUrl(options.getZincUrl())
            .setZincPublicSigningKeyUrl(options.getZincPublicSigningKeyUrl())
            .setBrassUrl(options.getBrassUrl())
            .setServiceType(options.getZincServiceType())
            .setReconnectorConfig(reconnectorConfig);

    if (options.getCopperControllerAddress().isPresent()) {
      builder.setCopperControllerAddress(options.getCopperControllerAddress().get());
    }

    builder.addAllCopperHostnameSuffix(options.getCopperHostnameSuffix());

    if (options.isIpSecEnabled().isPresent()) {
      builder.setIpsecDatapath(options.isIpSecEnabled().get());
    }
    if (options.isBridgeOnPpnEnabled().isPresent()) {
      builder.setBridgeOverPpn(options.isBridgeOnPpnEnabled().get());
    }
    if (options.getBridgeKeyLength().isPresent()) {
      builder.setCipherSuiteKeyLength(options.getBridgeKeyLength().get());
    }
    if (options.isBlindSigningEnabled().isPresent()) {
      builder.setEnableBlindSigning(options.isBlindSigningEnabled().get());
    }
    if (options.shouldInstallKryptonCrashSignalHandler().isPresent()) {
      builder.setInstallCrashSignalHandler(options.shouldInstallKryptonCrashSignalHandler().get());
    }
    if (options.getRekeyDuration().isPresent()) {
      Duration duration = options.getRekeyDuration().get();
      com.google.protobuf.Duration proto =
          com.google.protobuf.Duration.newBuilder()
              .setSeconds(duration.getSeconds())
              .setNanos(duration.getNano())
              .build();
      builder.setRekeyDuration(proto);
    }
    builder.setSafeDisconnectEnabled(options.isSafeDisconnectEnabled());

    return builder;
  }

  /** Creates a KryptonConfig with the options and feature state of this PPN instance. */
  private KryptonConfig createKryptonConfig() {
    return createKryptonConfigBuilder(this.options)
        .setSafeDisconnectEnabled(this.safeDisconnectEnabled)
        .build();
  }

  /**
   * Starts Krypton running. This will cause Krypton to authenticate and connect to its data plane.
   */
  private void startKrypton() throws PpnException {
    ensureBackgroundThread();

    synchronized (kryptonLock) {
      if (krypton != null) {
        throw new PpnException("Tried to start Krypton when it was already running.");
      }
      Log.w(TAG, "PPN creating Krypton.");
      krypton = kryptonFactory.createKrypton(this, backgroundExecutor);
      try {
        Log.w(TAG, "PPN starting Krypton.");
        krypton.start(createKryptonConfig());
      } catch (KryptonException e) {
        krypton = null;
        throw new PpnException("Unable to start Krypton.", e);
      }
    }
    Log.w(TAG, "PPN starting Xenon.");
    xenon.start();
    Log.w(TAG, "PPN finished starting Xenon.");
  }

  /**
   * Stops Xenon and Krypton, if it is running.
   *
   * @throws PpnException if Krypton.stop() threw.
   */
  private void stopKrypton() throws PpnException {
    Log.w(TAG, "PPN stopping Xenon.");
    xenon.stop();
    Log.w(TAG, "PPN stopped Xenon.");

    synchronized (kryptonLock) {
      if (krypton == null) {
        return;
      }
      try {
        Log.w(TAG, "PPN stopping Krypton.");
        krypton.stop();
        Log.w(TAG, "Krypton stop returned.");
      } catch (KryptonException e) {
        throw new PpnException("Unable to stop Krypton.", e);
      } finally {
        krypton = null;
      }
    }
  }

  /**
   * Logs PPN debug info to logcat in the background.
   *
   * @return the JSONObject that was logged.
   */
  @VisibleForTesting
  Task<JSONObject> logDebugInfoAsync(Duration timeout) {
    // A task that will be resolved either when the debug info has been printed, or after timeout.
    TaskCompletionSource<JSONObject> tcs = new TaskCompletionSource<>();
    AtomicBoolean finished = new AtomicBoolean(false);

    // Set up a timeout to log if getDebugJson doesn't appear to be responding.
    Runnable timeoutRunner =
        () -> {
          if (finished.compareAndSet(false, true)) {
            Log.i(TAG, "PPN appears to be deadlocked while fetching debug info.");
            tcs.trySetException(new TimeoutException("Call to getDebugJson timed out."));
          }
        };
    mainHandler.postDelayed(timeoutRunner, timeout.toMillis());

    // Get the debug info from the background thread.
    backgroundExecutor.execute(
        () -> {
          JSONObject debug = getDebugJson();
          if (finished.compareAndSet(false, true)) {
            mainHandler.removeCallbacks(timeoutRunner);
            Log.i(TAG, "PPN debug info: " + debug);
            tcs.setResult(debug);
          }
        });

    return tcs.getTask();
  }

  // This method exists because every time we do this logic, the Google linter insists on us using
  // an internal method for it. But this code is intended to be open sourced, so we can't use the
  // internal version.
  private static boolean isNullOrEmpty(@Nullable String s) {
    return s == null || s.isEmpty();
  }

  public void onStopService() {
    Log.w(TAG, "PPN Service has stopped.");
    // Grab the status reported from Krypton when it stopped, before resetting everything.
    PpnStatus status = kryptonStoppedStatus;
    kryptonStoppedStatus = KRYPTON_STOPPED_STATUS_UNKNOWN;
    vpnManager.setService(null);
    notificationManager.stopService();

    // Krypton should already be stopped, but if it's not, try to stop it.
    try {
      stopKrypton();
    } catch (PpnException e) {
      Log.e(TAG, "Unable to stop Krypton.", e);
    }

    // Stop the AccountRefresher if it hasn't been stopped.
    if (accountRefresher != null) {
      accountRefresher.stop();
      accountRefresher = null;
    }

    // Report to the listener why PPN was stopped.
    telemetry.notifyStopped();
    if (listener != null) {
      listener.onPpnStopped(status);
    }
  }

  @Override
  public void onNetworkAvailable(PpnNetwork ppnNetwork) {
    Log.w(TAG, "PPN received network available.");
    telemetry.notifyNetworkAvailable();
    backgroundExecutor.execute(
        () -> {
          try {
            synchronized (kryptonLock) {
              if (krypton != null) {
                NetworkInfo networkInfo =
                    NetworkInfo.newBuilder()
                        .setNetworkType(ppnNetwork.getNetworkType())
                        .setNetworkId(ppnNetwork.getNetworkId())
                        .build();
                Log.w(TAG, "Setting network on Krypton.");
                krypton.setNetwork(networkInfo);
                vpnManager.setNetwork(ppnNetwork);
              }
            }
          } catch (KryptonException e) {
            Log.e(TAG, "Unable to switch networks.", e);
          }
        });
  }

  @Override
  public void onNetworkUnavailable(NetworkUnavailableReason reason) {
    Log.w(TAG, "PPN received network unavailable.");
    telemetry.notifyNetworkUnavailable();
    backgroundExecutor.execute(
        () -> {
          try {
            synchronized (kryptonLock) {
              if (krypton != null) {
                Log.w(TAG, "Setting Krypton network unavailable.");
                krypton.setNoNetworkAvailable();
              }
            }
          } catch (KryptonException e) {
            Log.e(TAG, "Unable to set no network.", e);
          }
        });
  }

  @Override
  public void onNetworkStatusChanged(PpnNetwork ppnNetwork, ConnectionStatus connectionStatus) {
    Log.w(TAG, "Received network status changed - this is a no-op.");
  }

  private static void ensureBackgroundThread() {
    if (Looper.getMainLooper().isCurrentThread()) {
      throw new RuntimeException("Must not be called on the main thread.");
    }
  }
}
