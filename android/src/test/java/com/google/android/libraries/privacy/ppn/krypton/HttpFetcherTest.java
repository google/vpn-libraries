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

package com.google.android.libraries.privacy.ppn.krypton;

import static com.google.common.truth.Truth.assertThat;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import androidx.test.core.app.ApplicationProvider;
import com.google.android.libraries.privacy.ppn.internal.HttpRequest;
import com.google.android.libraries.privacy.ppn.internal.HttpResponse;
import com.google.android.libraries.privacy.ppn.internal.NetworkType;
import com.google.android.libraries.privacy.ppn.internal.json.Json;
import com.google.android.libraries.privacy.ppn.xenon.PpnNetwork;
import com.squareup.okhttp.mockwebserver.MockResponse;
import com.squareup.okhttp.mockwebserver.MockWebServer;
import com.squareup.okhttp.mockwebserver.RecordedRequest;
import com.squareup.okhttp.mockwebserver.SocketPolicy;
import java.time.Duration;
import java.util.Arrays;
import java.util.concurrent.FutureTask;
import okhttp3.Dns;
import okio.Buffer;
import org.json.JSONException;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;

/** Unit tests for {@link HttpFetcher}. */
@RunWith(RobolectricTestRunner.class)
public class HttpFetcherTest {
  private HttpFetcher httpFetcher;

  @Before
  public void setUp() {
    httpFetcher = new HttpFetcher(getSocketFactoryFactory());
    httpFetcher.setTimeout(Duration.ofSeconds(1));
  }

  private static BoundSocketFactoryFactory getSocketFactoryFactory() {
    return new TestBoundSocketFactoryFactory();
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

    boolean got = checkGet("http://example.com");

    assertThat(mockWebServer.getRequestCount()).isEqualTo(0);
    assertThat(got).isFalse();

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
    Context context = ApplicationProvider.getApplicationContext();
    ConnectivityManager manager =
        (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
    Network network = manager.getActiveNetwork();
    PpnNetwork ppnNetwork = new PpnNetwork(network, NetworkType.WIFI);
    FutureTask<Boolean> future = new FutureTask<>(() -> httpFetcher.checkGet(url, ppnNetwork));
    new Thread(future).start();
    return future.get();
  }
}
