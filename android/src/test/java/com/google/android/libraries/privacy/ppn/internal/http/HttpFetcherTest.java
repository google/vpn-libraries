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

package com.google.android.libraries.privacy.ppn.internal.http;

import static com.google.common.truth.Truth.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.when;

import android.net.Network;
import android.util.Log;
import com.google.android.libraries.privacy.ppn.internal.HttpRequest;
import com.google.android.libraries.privacy.ppn.internal.HttpResponse;
import com.google.android.libraries.privacy.ppn.internal.NetworkType;
import com.google.android.libraries.privacy.ppn.internal.json.Json;
import com.google.android.libraries.privacy.ppn.xenon.PpnNetwork;
import com.google.testing.mockito.Mocks;
import com.squareup.okhttp.mockwebserver.MockResponse;
import com.squareup.okhttp.mockwebserver.MockWebServer;
import com.squareup.okhttp.mockwebserver.RecordedRequest;
import com.squareup.okhttp.mockwebserver.SocketPolicy;
import java.net.InetAddress;
import java.time.Duration;
import java.util.Arrays;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.FutureTask;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.net.SocketFactory;
import okio.Buffer;
import org.json.JSONException;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.robolectric.RobolectricTestRunner;

/** Unit tests for {@link HttpFetcher}. */
@RunWith(RobolectricTestRunner.class)
public class HttpFetcherTest {
  private static final String TAG = "HttpFetcherTest";

  @Rule public Mocks mocks = new Mocks(this);
  @Mock private InetAddress mockAddress;
  @Mock private Network mockNetwork;
  @Mock private BoundSocketFactoryFactory socketFactoryFactory;

  private HttpFetcher httpFetcher;

  @Before
  public void setUp() {
    when(socketFactoryFactory.withCurrentNetwork()).thenReturn(SocketFactory.getDefault());
    when(socketFactoryFactory.withNetwork(any())).thenReturn(SocketFactory.getDefault());
    httpFetcher = new HttpFetcher(socketFactoryFactory);
    httpFetcher.setTimeout(Duration.ofSeconds(1));
  }

  private static JSONObject buildJsonBody() {
    final JSONObject message = new JSONObject();
    Json.put(message, "oauth_token", "some_token");
    return message;
  }

  private static HttpRequest buildHttpRequest(String url) {
    return HttpRequest.newBuilder()
        .setUrl(url)
        .putHeaders("header1", "header1_value")
        .putHeaders("header2", "header2_value")
        .setJsonBody(buildJsonBody().toString())
        .build();
  }

  private static JSONObject buildJsonResponse() throws JSONException {
    final JSONObject jsonContent = new JSONObject();
    jsonContent.put("jwt_token", "some_token");
    return jsonContent;
  }

  private static MockResponse buildPositiveMockResponse() throws JSONException {
    // mock a simple response with the JSON Content
    final MockResponse response = new MockResponse();
    final JSONObject jsonContent = buildJsonResponse();
    response.setBody(jsonContent.toString());
    response.setHeader("Content-Type", "application/json; charset=utf-8");
    return response;
  }

  private static MockResponse buildHugeMockResponse() {
    final MockResponse response = new MockResponse();
    final int length = 2048 * 1024; // 2 MB
    byte[] body = new byte[length];
    Arrays.fill(body, (byte) 'X');
    Buffer buffer = new Buffer();
    buffer.write(body);
    response.setBody(buffer);
    response.setHeader("Content-Type", "application/json; charset=utf-8");
    return response;
  }

  @Test
  public void testHttp() throws Exception {
    MockWebServer mockWebServer = new MockWebServer();
    mockWebServer.start();
    mockWebServer.enqueue(buildPositiveMockResponse());

    HttpResponse response = postJson(buildHttpRequest(mockWebServer.url("/").toString()));
    assertThat(mockWebServer.getRequestCount()).isEqualTo(1);
    RecordedRequest request = mockWebServer.takeRequest();
    String receivedBody = request.getBody().readUtf8();
    assertThat(receivedBody).isEqualTo(buildJsonBody().toString());
    assertThat(request.getHeader("Content-Type")).isEqualTo("application/json; charset=utf-8");

    assertThat(response.getStatus().getCode()).isEqualTo(200);
    assertThat(response.getJsonBody()).isEqualTo(buildJsonResponse().toString());
    mockWebServer.shutdown();
  }

  @Test
  public void testToInvalidHost() throws Exception {
    HttpResponse response = postJson(buildHttpRequest("http://unknown"));
    assertThat(response.getStatus().getCode()).isEqualTo(500);
    assertThat(response.getStatus().getMessage()).isEqualTo("IOException executing request");
  }

  @Test
  public void testNegativeResponse() throws Exception {
    MockWebServer mockWebServer = new MockWebServer();
    mockWebServer.start();

    mockWebServer.enqueue(
        new MockResponse().setResponseCode(402).setBody("Something went wrong in the server"));
    HttpResponse response = postJson(buildHttpRequest(mockWebServer.url("/").toString()));
    assertThat(mockWebServer.getRequestCount()).isEqualTo(1);
    RecordedRequest request = mockWebServer.takeRequest();
    String receivedBody = request.getBody().readUtf8();
    assertThat(receivedBody).isEqualTo(buildJsonBody().toString());
    assertThat(request.getHeader("Content-Type")).isEqualTo("application/json; charset=utf-8");
    assertThat(response.getStatus().getCode()).isEqualTo(402);
    assertThat(response.getJsonBody()).isEmpty();
    mockWebServer.shutdown();
  }

  @Test
  public void testNoResponse() throws Exception {
    MockWebServer mockWebServer = new MockWebServer();
    mockWebServer.start();
    mockWebServer.enqueue(new MockResponse().setSocketPolicy(SocketPolicy.NO_RESPONSE));

    HttpResponse response = postJson(buildHttpRequest(mockWebServer.url("/").toString()));

    assertThat(mockWebServer.getRequestCount()).isEqualTo(1);
    RecordedRequest request = mockWebServer.takeRequest();
    String receivedBody = request.getBody().readUtf8();
    assertThat(receivedBody).isEqualTo(buildJsonBody().toString());
    assertThat(request.getHeader("Content-Type")).isEqualTo("application/json; charset=utf-8");
    assertThat(response.getStatus().getCode()).isEqualTo(500);
    assertThat(response.getStatus().getMessage()).isEqualTo("IOException executing request");
    mockWebServer.shutdown();
  }

  @Test
  public void testDnsTimeout() throws Exception {
    MockWebServer mockWebServer = new MockWebServer();
    mockWebServer.start();
    // Override the DNS provider with one that will hang forever.
    FutureTask<Void> future =
        new FutureTask<>(
            () -> {
              return null;
            });
    httpFetcher.setDns(
        (hostname) -> {
          try {
            future.get();
          } catch (InterruptedException e) {
            throw new RuntimeException(e);
          } catch (Exception e) {
            throw new RuntimeException(e);
          }
          return Dns.SYSTEM.lookup(hostname);
        });

    HttpResponse response = postJson(buildHttpRequest("http://example.com"));

    assertThat(mockWebServer.getRequestCount()).isEqualTo(0);
    assertThat(response.getStatus().getCode()).isEqualTo(504);
    assertThat(response.getStatus().getMessage()).isEqualTo("request timed out");

    // Now that the request is finished, unblock the MockWebServer.
    future.run();
    mockWebServer.shutdown();
  }

  @Test
  public void testDnsTimeoutOnCheckGet() throws Exception {
    MockWebServer mockWebServer = new MockWebServer();
    mockWebServer.start();
    // Override the DNS provider with one that will hang forever.
    FutureTask<Void> future = new FutureTask<>(() -> null);
    httpFetcher.setDns(
        (hostname) -> {
          try {
            future.get();
          } catch (InterruptedException e) {
            throw new RuntimeException(e);
          } catch (Exception e) {
            throw new RuntimeException(e);
          }
          return Dns.SYSTEM.lookup(hostname);
        });

    boolean got = checkGet("http://example.com");

    assertThat(mockWebServer.getRequestCount()).isEqualTo(0);
    assertThat(got).isFalse();

    // Now that the request is finished, unblock the MockWebServer.
    future.run();
    mockWebServer.shutdown();
  }

  @Test
  public void testDnsCachingOnCheckGetTimesOutInitially() throws Exception {
    MockWebServer mockWebServer = new MockWebServer();
    mockWebServer.start();
    // Override the DNS provider with one that will hang forever.
    FutureTask<Void> future = new FutureTask<>(() -> null);
    Dns hangingDns =
        ((hostname) -> {
          try {
            future.get();
          } catch (InterruptedException e) {
            throw new RuntimeException(e);
          } catch (Exception e) {
            throw new RuntimeException(e);
          }
          return Dns.SYSTEM.lookup(hostname);
        });
    ExecutorService executorService = Executors.newSingleThreadExecutor();
    // Don't wait very long before using the cache, if available.
    Duration cacheTimeout = Duration.ofMillis(10);
    // The longer timeout should exceed the overall request, so that the lookup appears to hang.
    Duration lookupTimeout = Duration.ofSeconds(10);
    Dns cachedDns = new CachedDns(hangingDns, cacheTimeout, lookupTimeout, executorService);
    httpFetcher.setDns(cachedDns);

    boolean gotUrl = checkGet("http://example.com");

    assertThat(mockWebServer.getRequestCount()).isEqualTo(0);
    assertThat(gotUrl).isFalse();

    // Now that the request is finished, unblock the MockWebServer.
    future.run();
    mockWebServer.shutdown();
  }

  @Test
  public void testDnsCachingOnCheckGetHandlesTimeout() throws Exception {
    MockWebServer mockWebServer = new MockWebServer();
    mockWebServer.start();
    // Override the DNS provider with one that will hang forever.
    FutureTask<Void> future = new FutureTask<>(() -> null);
    Dns hangingDns =
        ((hostname) -> {
          try {
            future.get();
          } catch (InterruptedException e) {
            throw new RuntimeException(e);
          } catch (Exception e) {
            throw new RuntimeException(e);
          }
          return Dns.SYSTEM.lookup(hostname);
        });
    ExecutorService executorService = Executors.newSingleThreadExecutor();
    // Don't wait very long before using the cache, if available.
    Duration cacheTimeout = Duration.ofMillis(10);
    // Have a short timeout so that the lookup fails the request.
    Duration lookupTimeout = Duration.ofMillis(10);
    Dns cachedDns = new CachedDns(hangingDns, cacheTimeout, lookupTimeout, executorService);
    httpFetcher.setDns(cachedDns);

    boolean got = checkGet("http://example.com");

    assertThat(mockWebServer.getRequestCount()).isEqualTo(0);
    assertThat(got).isFalse();

    // Now that the request is finished, unblock the MockWebServer.
    future.run();
    mockWebServer.shutdown();
  }

  @Test
  public void testDnsCachingOnCheckGetSucceedsOnSecondRun() throws Exception {
    // Set up the mock web server to respond to a GET request.
    MockWebServer mockWebServer = new MockWebServer();
    mockWebServer.start();
    mockWebServer.enqueue(new MockResponse().setResponseCode(200));
    Log.e(TAG, "MockWebServer serving at " + mockWebServer.getHostName());

    // Create a Dns implementation that we can make hang or not.
    AtomicBoolean shouldHang = new AtomicBoolean(false);

    // A future makes it easy to implement hanging.
    FutureTask<Void> future = new FutureTask<>(() -> null);

    Dns mockDns =
        (hostname) -> {
          Log.e(TAG, "Got DNS lookup request for " + hostname);
          if (shouldHang.get()) {
            Log.e(TAG, "Going to hang forever looking up " + hostname);
            try {
              future.get();
            } catch (InterruptedException e) {
              throw new RuntimeException(e);
            } catch (Exception e) {
              throw new RuntimeException(e);
            }
          }
          Log.e(TAG, "Returning IP for " + hostname);
          return Dns.SYSTEM.lookup(hostname);
        };

    // Wrap that Dns in a caching layer.
    ExecutorService executorService = Executors.newSingleThreadExecutor();
    // It doesn't really matter what the timeouts are, since the underlying lookup can hang forever.
    Duration cacheTimeout = Duration.ofMillis(10);
    Duration lookupTimeout = Duration.ofMillis(10);
    Dns cachedDns = new CachedDns(mockDns, cacheTimeout, lookupTimeout, executorService);

    // Query the cachedDns once to prime the cache.
    cachedDns.lookup(mockWebServer.getHostName());

    // Tell the mock DNS to hang forever on subsequent requests.
    shouldHang.set(true);

    httpFetcher.setDns(cachedDns);
    boolean got = checkGet(mockWebServer.url("/").toString());

    assertThat(mockWebServer.getRequestCount()).isEqualTo(1);
    assertThat(got).isTrue();

    // Now that the request is finished, unblock the MockWebServer.
    future.run();
    mockWebServer.shutdown();
  }

  @Test
  public void testEmpty() throws Exception {
    MockWebServer mockWebServer = new MockWebServer();
    mockWebServer.start();
    mockWebServer.enqueue(new MockResponse().setResponseCode(200));
    HttpResponse response = postJson(buildHttpRequest(mockWebServer.url("/").toString()));
    assertThat(mockWebServer.getRequestCount()).isEqualTo(1);
    RecordedRequest request = mockWebServer.takeRequest();
    String receivedBody = request.getBody().readUtf8();
    assertThat(receivedBody).isEqualTo(buildJsonBody().toString());
    assertThat(request.getHeader("Content-Type")).isEqualTo("application/json; charset=utf-8");
    assertThat(response.getStatus().getCode()).isEqualTo(500);
    assertThat(response.getStatus().getMessage()).isEqualTo("invalid response JSON");
    mockWebServer.shutdown();
  }

  @Test
  public void testMalformedJsonBody() throws Exception {
    MockWebServer mockWebServer = new MockWebServer();
    mockWebServer.start();
    mockWebServer.enqueue(new MockResponse().setBody("{\"abc:123}").setResponseCode(200));
    HttpResponse response = postJson(buildHttpRequest(mockWebServer.url("/").toString()));
    assertThat(mockWebServer.getRequestCount()).isEqualTo(1);
    RecordedRequest request = mockWebServer.takeRequest();
    String receivedBody = request.getBody().readUtf8();
    assertThat(receivedBody).isEqualTo(buildJsonBody().toString());
    assertThat(request.getHeader("Content-Type")).isEqualTo("application/json; charset=utf-8");
    assertThat(response.getStatus().getCode()).isEqualTo(500);
    assertThat(response.getStatus().getMessage()).isEqualTo("invalid response JSON");
    mockWebServer.shutdown();
  }

  @Test
  public void testHugeResponse() throws Exception {
    MockWebServer mockWebServer = new MockWebServer();
    mockWebServer.start();
    mockWebServer.enqueue(buildHugeMockResponse());
    HttpResponse response = postJson(buildHttpRequest(mockWebServer.url("/").toString()));
    assertThat(mockWebServer.getRequestCount()).isEqualTo(1);
    RecordedRequest request = mockWebServer.takeRequest();
    String receivedBody = request.getBody().readUtf8();
    assertThat(receivedBody).isEqualTo(buildJsonBody().toString());
    assertThat(request.getHeader("Content-Type")).isEqualTo("application/json; charset=utf-8");
    assertThat(response.getStatus().getCode()).isEqualTo(500);
    assertThat(response.getStatus().getMessage()).isEqualTo("response length exceeds limit of 1MB");
    mockWebServer.shutdown();
  }

  @Test
  public void testCheckGet() throws Exception {
    MockWebServer mockWebServer = new MockWebServer();
    mockWebServer.start();
    mockWebServer.enqueue(buildPositiveMockResponse());

    boolean got = checkGet(mockWebServer.url("/").toString());

    assertThat(mockWebServer.getRequestCount()).isEqualTo(1);
    RecordedRequest request = mockWebServer.takeRequest();
    assertThat(request.getMethod()).isEqualTo("GET");
    assertThat(got).isTrue();

    mockWebServer.shutdown();
  }

  @Test
  public void testLookupDns() throws Exception {
    doReturn("127.0.0.1").when(mockAddress).getHostAddress();

    Dns mockDns = (hostname) -> Arrays.asList(mockAddress);
    httpFetcher.setDns(mockDns);

    String address = httpFetcher.lookupDns("example.com");
    assertThat(address).isEqualTo("127.0.0.1");
  }

  @Test
  public void testLookupDnsReturnsEmpty() throws Exception {
    Dns mockDns = (hostname) -> Arrays.asList();
    httpFetcher.setDns(mockDns);

    String address = httpFetcher.lookupDns("example.com");
    assertThat(address).isNull();
  }

  /**
   * Runs a postJson request in the background and blocks until it returns. This is needed because
   * the synchronous postJson method cannot be called on the main thread.
   */
  private HttpResponse postJson(HttpRequest request) throws Exception {
    FutureTask<HttpResponse> future = new FutureTask<>(() -> httpFetcher.postJson(request));
    new Thread(future).start();
    return future.get();
  }

  /**
   * Runs a checkGet request in the background and blocks until it returns. This is needed because
   * the synchronous checkGet method cannot be called on the main thread.
   */
  private boolean checkGet(String url) throws Exception {
    // Override the multinetwork DNS lookup, since the test framework doesn't support it.
    when(mockNetwork.getAllByName(anyString()))
        .then(invocation -> InetAddress.getAllByName(invocation.getArgument(0)));
    PpnNetwork ppnNetwork = new PpnNetwork(mockNetwork, NetworkType.WIFI);
    FutureTask<Boolean> future = new FutureTask<>(() -> httpFetcher.checkGet(url, ppnNetwork));
    new Thread(future).start();
    return future.get();
  }
}
