// Copyright 2021 Google LLC
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

package com.google.android.libraries.privacy.ppn.internal.http;

import static java.util.concurrent.TimeUnit.MILLISECONDS;

import android.util.Log;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Duration;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.TimeoutException;

/** A shared DNS cache that wraps Dns to add caching. */
public class CachedDns implements Dns {
  private static final String TAG = "CachedDns";

  private final Dns dns;
  private final Duration cacheTimeout;
  private final Duration lookupTimeout;
  private final Map<String, List<InetAddress>> cache = Collections.synchronizedMap(new HashMap<>());
  private final ExecutorService backgroundExecutor;

  /**
   * Constructs a cached DNS.
   *
   * @param dns The Dns to wrap.
   * @param cacheTimeout How long to try requests before falling back to the cache.
   * @param lookupTimeout How much additional time to wait for the lookup before stopping it.
   * @param backgroundExecutor Executor to use when running Dns requests.
   */
  public CachedDns(
      Dns dns, Duration cacheTimeout, Duration lookupTimeout, ExecutorService backgroundExecutor) {
    this.dns = dns;
    this.cacheTimeout = cacheTimeout;
    this.lookupTimeout = lookupTimeout;
    this.backgroundExecutor = backgroundExecutor;
  }

  @Override
  public List<InetAddress> lookup(String host) throws UnknownHostException {
    // Try to do the DNS lookup in a background thread.
    Future<List<InetAddress>> future =
        backgroundExecutor.submit(
            () -> {
              try {
                List<InetAddress> addresses = dns.lookup(host);
                Log.e(TAG, "DNS lookup succeeded for " + host);
                cache.put(host, addresses);
                return addresses;

              } catch (UnknownHostException e) {
                Log.e(TAG, "DNS lookup returned unknown host for " + host, e);
                throw e;
              }
            });

    try {
      try {
        // Wait for it to finish, unless it times out.
        return future.get(cacheTimeout.toMillis(), MILLISECONDS);

      } catch (TimeoutException e) {
        Log.e(
            TAG,
            "DNS lookup did not complete before cache timeout (" + cacheTimeout + "): " + host,
            e);

        // It timed out, so check the cache first.
        List<InetAddress> cached = cache.getOrDefault(host, null);
        if (cached != null) {
          // Cancel the lookup so it doesn't go on forever.
          future.cancel(true);
          Log.e(TAG, "Using cached DNS address for " + host);
          return cached;
        }
        Log.e(TAG, "Waiting additional time for DNS lookup for " + host);

        // Well, it timed out or failed and wasn't in the cache, so give it additional time.
        try {
          return future.get(lookupTimeout.toMillis(), MILLISECONDS);
        } catch (TimeoutException innerTimeout) {
          // It timed out both times, so give up.
          // The system DNS would just hang forever here, but we can't do that.
          Log.e(TAG, "DNS lookup timed out (" + lookupTimeout + ") for " + host, innerTimeout);
          future.cancel(true);
          throw new UnknownHostException(host);
        }
      }
    } catch (InterruptedException | ExecutionException e) {
      // This was not a timeout, so there's not really any way to recover.
      Log.e(TAG, "DNS lookup failed for " + host, e);
      throw new UnknownHostException(host);
    }
  }
}
