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

package com.google.android.libraries.privacy.ppn.internal.http;

import static com.google.common.truth.Truth.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

import android.net.Network;
import android.util.Log;
import com.google.android.libraries.privacy.ppn.Dns;
import com.google.android.libraries.privacy.ppn.PpnStatus;
import com.google.android.libraries.privacy.ppn.internal.HttpRequest;
import com.google.android.libraries.privacy.ppn.internal.HttpResponse;
import com.google.android.libraries.privacy.ppn.internal.NetworkInfo.AddressFamily;
import com.google.android.libraries.privacy.ppn.internal.PpnStatusDetails;
import com.google.android.libraries.privacy.ppn.internal.json.Json;
import com.google.common.net.InetAddresses;
import com.google.protobuf.Any;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.rpc.Code;
import com.google.rpc.Status;
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
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;
import org.robolectric.RobolectricTestRunner;

/** Unit tests for {@link HttpFetcher}. */
@RunWith(RobolectricTestRunner.class)
public class HttpFetcherTest {
  private static final String TAG = "HttpFetcherTest";
  private static final String VALID_JSON_REQUEST_BODY = "{\"foo\":\"bar\"}";
  private static final String VALID_JSON_RESPONSE_BODY = "{\"baz\":\"qux\"}";
  private static final byte[] VALID_PROTO_REQUEST_BODY = {0x01, 0x02, 0x03};
  private static final byte[] VALID_PROTO_RESPONSE_BODY = {0x03, 0x02, 0x01};

  private static final PpnStatusDetails VALID_DETAILS_PROTO = buildValidDetailsProto();
  private static final Status VALID_ERROR_PROTO = buildValidErrorProto();
  private static final String VALID_ERROR_JSON = buildValidErrorJson();

  @Rule public final MockitoRule mocks = MockitoJUnit.rule();
  private final InetAddress address = InetAddresses.forString("127.0.0.1");
  @Mock private Network mockNetwork;
  @Mock private BoundSocketFactoryFactory socketFactoryFactory;

  private HttpFetcher httpFetcher;
  private MockWebServer mockWebServer;

  @Before
  public void setUp() throws Exception {
    when(socketFactoryFactory.withCurrentNetwork()).thenReturn(SocketFactory.getDefault());
    when(socketFactoryFactory.withNetwork(any())).thenReturn(SocketFactory.getDefault());
    httpFetcher = new HttpFetcher(socketFactoryFactory);
    httpFetcher.setTimeout(Duration.ofSeconds(1));

    mockWebServer = new MockWebServer();
    mockWebServer.start();
  }

  @After
  public void tearDown() throws Exception {
    mockWebServer.shutdown();
  }

  private static PpnStatusDetails buildValidDetailsProto() {
    return PpnStatusDetails.newBuilder()
        .setDetailedErrorCode(PpnStatusDetails.DetailedErrorCode.VPN_PERMISSION_REVOKED)
        .build();
  }

  private static Status buildValidErrorProto() {
    Any details =
        Any.newBuilder()
            .setTypeUrl(PpnStatus.DETAILS_TYPE_URL)
            .setValue(VALID_DETAILS_PROTO.toByteString())
            .build();

    return Status.newBuilder()
        .setCode(Code.PERMISSION_DENIED_VALUE)
        .setMessage("Permission Denied")
        .addDetails(details)
        .build();
  }

  private static String buildValidErrorJson() {
    JSONObject statusDetails = new JSONObject();
    // In proto JSON, uint64 is encoded as a String.
    Json.put(
        statusDetails,
        "authInternalErrorCode",
        Long.toString(VALID_DETAILS_PROTO.getAuthInternalErrorCode()));
    Json.put(statusDetails, "@type", PpnStatus.DETAILS_TYPE_URL);

    JSONArray details = new JSONArray();
    details.put(statusDetails);

    JSONObject error = new JSONObject();
    Json.put(error, "code", VALID_ERROR_PROTO.getCode());
    Json.put(error, "message", VALID_ERROR_PROTO.getMessage());
    Json.put(error, "details", details);
    Json.put(error, "status", "PERMISSION_DENIED");

    return error.toString();
  }

  private static HttpRequest buildJsonHttpRequest(String url) {
    return HttpRequest.newBuilder()
        .setUrl(url)
        .putHeaders("header1", "header1_value")
        .putHeaders("header2", "header2_value")
        .setJsonBody(VALID_JSON_REQUEST_BODY)
        .build();
  }

  private static HttpRequest buildProtoHttpRequest(String url) {
    return HttpRequest.newBuilder()
        .setUrl(url)
        .putHeaders("header1", "header1_value")
        .putHeaders("header2", "header2_value")
        .setProtoBody(ByteString.copyFrom(VALID_PROTO_REQUEST_BODY))
        .build();
  }

  private static MockResponse buildHugeMockResponse() {
    final MockResponse response = new MockResponse();
    final int length = 2048 * 1024; // 2 MB
    byte[] body = new byte[length];
    Arrays.fill(body, (byte) 'X');
    Buffer buffer = new Buffer();
    buffer.write(body);
    response.setBody(buffer);
    return response;
  }

  private static MockResponse buildHugeJsonMockResponse() {
    return buildHugeMockResponse().setHeader("Content-Type", "application/json; charset=utf-8");
  }

  private static MockResponse buildHugeProtoMockResponse() {
    return buildHugeMockResponse().setHeader("Content-Type", "application/x-protobuf");
  }

  @Test
  public void testHttpJson() throws Exception {
    mockWebServer.enqueue(
        new MockResponse()
            .setHeader("Content-Type", "application/json; charset=utf-8")
            .setStatus("HTTP/1.1 200 OK")
            .setBody(VALID_JSON_RESPONSE_BODY));

    HttpResponse response = postJson(buildJsonHttpRequest(mockWebServer.url("/").toString()));
    assertThat(mockWebServer.getRequestCount()).isEqualTo(1);
    RecordedRequest request = mockWebServer.takeRequest();
    String receivedBody = request.getBody().readUtf8();
    assertThat(receivedBody).isEqualTo(VALID_JSON_REQUEST_BODY);
    assertThat(request.getHeader("Content-Type")).isEqualTo("application/json; charset=utf-8");

    assertThat(response.getStatus().getCode()).isEqualTo(200);
    assertThat(response.getStatus().getMessage()).isEqualTo("OK");
    assertThat(response.getJsonBody()).isEqualTo(VALID_JSON_RESPONSE_BODY);
    assertThat(response.hasProtoBody()).isFalse();
  }

  @Test
  public void testHttpProto() throws Exception {
    Buffer requestBody = new Buffer();
    requestBody.write(VALID_PROTO_RESPONSE_BODY);
    mockWebServer.enqueue(
        new MockResponse()
            .setHeader("Content-Type", "application/x-protobuf")
            .setStatus("HTTP/1.1 200 OK")
            .setBody(requestBody));

    HttpResponse response = postJson(buildProtoHttpRequest(mockWebServer.url("/").toString()));
    assertThat(mockWebServer.getRequestCount()).isEqualTo(1);
    RecordedRequest request = mockWebServer.takeRequest();
    byte[] receivedBody = request.getBody().readByteArray();
    assertThat(receivedBody).isEqualTo(VALID_PROTO_REQUEST_BODY);
    assertThat(request.getHeader("Content-Type")).isEqualTo("application/x-protobuf");

    assertThat(response.getStatus().getCode()).isEqualTo(200);
    assertThat(response.getStatus().getMessage()).isEqualTo("OK");
    assertThat(response.getProtoBody().toByteArray()).isEqualTo(VALID_PROTO_RESPONSE_BODY);
    assertThat(response.hasJsonBody()).isFalse();
  }

  @Test
  public void testToInvalidHost() throws Exception {
    HttpResponse response = postJson(buildJsonHttpRequest("http://unknown"));
    assertThat(response.getStatus().getCode()).isEqualTo(500);
    assertThat(response.getStatus().getMessage()).isEqualTo("IOException executing request");
  }

  @Test
  public void testJsonResponseWithErrorStatus() throws Exception {
    mockWebServer.enqueue(
        new MockResponse()
            .setStatus("HTTP/1.1 402 Payment Required")
            .addHeader("Content-Type: application/json; charset=utf-8")
            .setBody(VALID_JSON_RESPONSE_BODY));

    HttpResponse response = postJson(buildJsonHttpRequest(mockWebServer.url("/").toString()));

    assertThat(mockWebServer.getRequestCount()).isEqualTo(1);
    RecordedRequest request = mockWebServer.takeRequest();
    String receivedBody = request.getBody().readUtf8();
    assertThat(receivedBody).isEqualTo(VALID_JSON_REQUEST_BODY);
    assertThat(request.getHeader("Content-Type")).isEqualTo("application/json; charset=utf-8");

    assertThat(response.getStatus().getCode()).isEqualTo(402);
    assertThat(response.getStatus().getMessage()).isEqualTo("Payment Required");
    assertThat(response.getJsonBody()).isEqualTo(VALID_JSON_RESPONSE_BODY);
    assertThat(response.hasProtoBody()).isFalse();
  }

  @Test
  public void testJsonResponseWithTextStatus() throws Exception {
    mockWebServer.enqueue(
        new MockResponse()
            .setStatus("HTTP/1.1 402 Payment Required")
            .addHeader("Content-Type: application/json; charset=utf-8")
            .setBody("Something went wrong in the server"));

    HttpResponse response = postJson(buildJsonHttpRequest(mockWebServer.url("/").toString()));

    assertThat(mockWebServer.getRequestCount()).isEqualTo(1);
    RecordedRequest request = mockWebServer.takeRequest();
    String receivedBody = request.getBody().readUtf8();
    assertThat(receivedBody).isEqualTo(VALID_JSON_REQUEST_BODY);
    assertThat(request.getHeader("Content-Type")).isEqualTo("application/json; charset=utf-8");

    assertThat(response.getStatus().getCode()).isEqualTo(402);
    assertThat(response.getStatus().getMessage()).isEqualTo("Payment Required");
    assertThat(response.hasJsonBody()).isFalse();
    assertThat(response.hasProtoBody()).isFalse();
  }

  @Test
  public void testProtoResponseWithErrorStatus() throws Exception {
    Buffer responseBody = new Buffer();
    responseBody.write(VALID_ERROR_PROTO.toByteArray());
    mockWebServer.enqueue(
        new MockResponse()
            .setStatus("HTTP/1.1 402 Payment Required")
            .addHeader("Content-Type: application/x-protobuf")
            .setBody(responseBody));

    HttpResponse response = postJson(buildProtoHttpRequest(mockWebServer.url("/").toString()));

    assertThat(mockWebServer.getRequestCount()).isEqualTo(1);
    RecordedRequest request = mockWebServer.takeRequest();
    assertThat(request.getHeader("Content-Type")).isEqualTo("application/x-protobuf");
    assertThat(request.getBody().readByteArray()).isEqualTo(VALID_PROTO_REQUEST_BODY);

    assertThat(response.getStatus().getCode()).isEqualTo(402);
    assertThat(response.getStatus().getMessage()).isEqualTo("Payment Required");
    assertThat(response.hasJsonBody()).isFalse();

    Status status =
        Status.parseFrom(response.getProtoBody(), ExtensionRegistryLite.getEmptyRegistry());
    assertThat(status.getCode()).isEqualTo(VALID_ERROR_PROTO.getCode());
    assertThat(status.getMessage()).isEqualTo(VALID_ERROR_PROTO.getMessage());
    assertThat(status.getDetailsList()).hasSize(1);
    assertThat(status.getDetailsList().get(0).getTypeUrl()).isEqualTo(PpnStatus.DETAILS_TYPE_URL);

    PpnStatusDetails details =
        PpnStatusDetails.parseFrom(
            status.getDetailsList().get(0).getValue(), ExtensionRegistryLite.getEmptyRegistry());
    assertThat(details.getDetailedErrorCode())
        .isEqualTo(VALID_DETAILS_PROTO.getDetailedErrorCode());
  }

  @Test
  public void testNoResponse() throws Exception {
    mockWebServer.enqueue(new MockResponse().setSocketPolicy(SocketPolicy.NO_RESPONSE));

    HttpResponse response = postJson(buildJsonHttpRequest(mockWebServer.url("/").toString()));

    assertThat(mockWebServer.getRequestCount()).isEqualTo(1);
    RecordedRequest request = mockWebServer.takeRequest();
    String receivedBody = request.getBody().readUtf8();
    assertThat(receivedBody).isEqualTo(VALID_JSON_REQUEST_BODY);
    assertThat(request.getHeader("Content-Type")).isEqualTo("application/json; charset=utf-8");

    assertThat(response.getStatus().getCode()).isEqualTo(500);
    assertThat(response.getStatus().getMessage()).isEqualTo("IOException executing request");
    assertThat(response.hasJsonBody()).isFalse();
    assertThat(response.hasProtoBody()).isFalse();
  }

  @Test
  public void testDnsTimeout() throws Exception {
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

    HttpResponse response = postJson(buildJsonHttpRequest("http://example.com"));

    assertThat(mockWebServer.getRequestCount()).isEqualTo(0);
    assertThat(response.getStatus().getCode()).isEqualTo(504);
    assertThat(response.getStatus().getMessage()).isEqualTo("request timed out");

    // Now that the request is finished, unblock the MockWebServer.
    future.run();
  }

  @Test
  public void testDnsTimeoutOnCheckGet() throws Exception {
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
  }

  @Test
  public void testDnsCachingOnCheckGetTimesOutInitially() throws Exception {
    // Override the DNS provider with one that will hang forever.
    FutureTask<Void> future = new FutureTask<>(() -> null);
    Dns hangingDns =
        (hostname) -> {
          try {
            future.get();
          } catch (InterruptedException e) {
            throw new RuntimeException(e);
          } catch (Exception e) {
            throw new RuntimeException(e);
          }
          return Dns.SYSTEM.lookup(hostname);
        };
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
  }

  @Test
  public void testDnsCachingOnCheckGetHandlesTimeout() throws Exception {
    // Override the DNS provider with one that will hang forever.
    FutureTask<Void> future = new FutureTask<>(() -> null);
    Dns hangingDns =
        (hostname) -> {
          try {
            future.get();
          } catch (InterruptedException e) {
            throw new RuntimeException(e);
          } catch (Exception e) {
            throw new RuntimeException(e);
          }
          return Dns.SYSTEM.lookup(hostname);
        };
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
  }

  @Test
  public void testDnsCachingOnCheckGetSucceedsOnSecondRun() throws Exception {
    mockWebServer.enqueue(new MockResponse().setStatus("HTTP/1.1 200 OK"));
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
  }

  @Test
  public void testEmptyJson_withOkStatus() throws Exception {
    // A response with 200 and no JSON is considered malformed.
    mockWebServer.enqueue(
        new MockResponse()
            .setStatus("HTTP/1.1 200 OK")
            .addHeader("Content-Type: application/json; charset=utf-8"));

    HttpResponse response = postJson(buildJsonHttpRequest(mockWebServer.url("/").toString()));

    assertThat(mockWebServer.getRequestCount()).isEqualTo(1);
    RecordedRequest request = mockWebServer.takeRequest();
    String receivedBody = request.getBody().readUtf8();
    assertThat(receivedBody).isEqualTo(VALID_JSON_REQUEST_BODY);
    assertThat(request.getHeader("Content-Type")).isEqualTo("application/json; charset=utf-8");

    assertThat(response.getStatus().getCode()).isEqualTo(500);
    assertThat(response.getStatus().getMessage()).isEqualTo("invalid response JSON");
    assertThat(response.hasJsonBody()).isFalse();
    assertThat(response.hasProtoBody()).isFalse();
  }

  @Test
  public void testEmptyProtoSuccess() throws Exception {
    // A response with 200 and no proto bytes is acceptable, as a default proto can encode that way.
    mockWebServer.enqueue(
        new MockResponse()
            .setStatus("HTTP/1.1 200 OK")
            .addHeader("Content-Type: application/x-protobuf"));

    HttpResponse response = postJson(buildProtoHttpRequest(mockWebServer.url("/").toString()));

    assertThat(mockWebServer.getRequestCount()).isEqualTo(1);
    RecordedRequest request = mockWebServer.takeRequest();
    assertThat(request.getBody().readByteArray()).isEqualTo(VALID_PROTO_REQUEST_BODY);
    assertThat(request.getHeader("Content-Type")).isEqualTo("application/x-protobuf");

    assertThat(response.getStatus().getCode()).isEqualTo(200);
    assertThat(response.getStatus().getMessage()).isEqualTo("OK");
    assertThat(response.hasProtoBody()).isTrue();
    assertThat(response.getProtoBody()).isEqualTo(ByteString.EMPTY);
    assertThat(response.hasJsonBody()).isFalse();
  }

  @Test
  public void testEmptyJsonError() throws Exception {
    mockWebServer.enqueue(
        new MockResponse()
            .setStatus("HTTP/1.1 400 Bad Request")
            .addHeader("Content-Type: application/json; charset=utf-8"));

    HttpResponse response = postJson(buildJsonHttpRequest(mockWebServer.url("/").toString()));

    assertThat(mockWebServer.getRequestCount()).isEqualTo(1);
    RecordedRequest request = mockWebServer.takeRequest();
    String receivedBody = request.getBody().readUtf8();
    assertThat(receivedBody).isEqualTo(VALID_JSON_REQUEST_BODY);
    assertThat(request.getHeader("Content-Type")).isEqualTo("application/json; charset=utf-8");

    assertThat(response.getStatus().getCode()).isEqualTo(400);
    assertThat(response.getStatus().getMessage()).isEqualTo("Bad Request");
    assertThat(response.hasJsonBody()).isFalse();
    assertThat(response.hasProtoBody()).isFalse();
  }

  @Test
  public void testEmptyProtoError() throws Exception {
    mockWebServer.enqueue(
        new MockResponse()
            .setStatus("HTTP/1.1 400 Bad Request")
            .addHeader("Content-Type: application/x-protobuf"));

    HttpResponse response = postJson(buildJsonHttpRequest(mockWebServer.url("/").toString()));

    assertThat(mockWebServer.getRequestCount()).isEqualTo(1);
    RecordedRequest request = mockWebServer.takeRequest();
    String receivedBody = request.getBody().readUtf8();
    assertThat(receivedBody).isEqualTo(VALID_JSON_REQUEST_BODY);
    assertThat(request.getHeader("Content-Type")).isEqualTo("application/json; charset=utf-8");

    assertThat(response.getStatus().getCode()).isEqualTo(400);
    assertThat(response.getStatus().getMessage()).isEqualTo("Bad Request");
    assertThat(response.getProtoBody()).isEqualTo(ByteString.EMPTY);
    assertThat(response.hasJsonBody()).isFalse();
  }

  @Test
  public void testProtoError() throws Exception {
    Buffer responseBody = new Buffer();
    responseBody.write(VALID_ERROR_PROTO.toByteArray());
    mockWebServer.enqueue(
        new MockResponse()
            .setStatus("HTTP/1.1 400 Bad Request")
            .addHeader("Content-Type: application/x-protobuf")
            .setBody(responseBody));

    HttpResponse response = postJson(buildJsonHttpRequest(mockWebServer.url("/").toString()));

    assertThat(mockWebServer.getRequestCount()).isEqualTo(1);
    RecordedRequest request = mockWebServer.takeRequest();
    String receivedBody = request.getBody().readUtf8();
    assertThat(receivedBody).isEqualTo(VALID_JSON_REQUEST_BODY);
    assertThat(request.getHeader("Content-Type")).isEqualTo("application/json; charset=utf-8");

    assertThat(response.getStatus().getCode()).isEqualTo(400);
    assertThat(response.getStatus().getMessage()).isEqualTo("Bad Request");
    assertThat(response.hasJsonBody()).isFalse();

    Status status =
        Status.parseFrom(response.getProtoBody(), ExtensionRegistryLite.getEmptyRegistry());
    assertThat(status.getCode()).isEqualTo(VALID_ERROR_PROTO.getCode());
    assertThat(status.getMessage()).isEqualTo(VALID_ERROR_PROTO.getMessage());
    assertThat(status.getDetailsList()).hasSize(1);
    assertThat(status.getDetailsList().get(0).getTypeUrl()).isEqualTo(PpnStatus.DETAILS_TYPE_URL);

    PpnStatusDetails details =
        PpnStatusDetails.parseFrom(
            status.getDetailsList().get(0).getValue(), ExtensionRegistryLite.getEmptyRegistry());
    assertThat(details.getDetailedErrorCode())
        .isEqualTo(VALID_DETAILS_PROTO.getDetailedErrorCode());
  }

  @Test
  public void testJsonError() throws Exception {
    mockWebServer.enqueue(
        new MockResponse()
            .setStatus("HTTP/1.1 400 Bad Request")
            .addHeader("Content-Type: application/json; charset=utf-8")
            .setBody(VALID_ERROR_JSON));

    HttpResponse response = postJson(buildJsonHttpRequest(mockWebServer.url("/").toString()));

    assertThat(mockWebServer.getRequestCount()).isEqualTo(1);
    RecordedRequest request = mockWebServer.takeRequest();
    String receivedBody = request.getBody().readUtf8();
    assertThat(receivedBody).isEqualTo(VALID_JSON_REQUEST_BODY);
    assertThat(request.getHeader("Content-Type")).isEqualTo("application/json; charset=utf-8");

    assertThat(response.getStatus().getCode()).isEqualTo(400);
    assertThat(response.getStatus().getMessage()).isEqualTo("Bad Request");
    assertThat(response.hasJsonBody()).isTrue();

    JSONObject status = new JSONObject(response.getJsonBody());
    assertThat(status.get("code")).isEqualTo(VALID_ERROR_PROTO.getCode());
    assertThat(status.get("message")).isEqualTo(VALID_ERROR_PROTO.getMessage());
    assertThat(status.get("status")).isEqualTo("PERMISSION_DENIED");

    JSONArray details = status.getJSONArray("details");
    assertThat(details.length()).isEqualTo(1);

    JSONObject statusDetails = details.getJSONObject(0);
    assertThat(statusDetails.get("@type")).isEqualTo(PpnStatus.DETAILS_TYPE_URL);
    assertThat(statusDetails.get("authInternalErrorCode"))
        .isEqualTo(Long.toString(VALID_DETAILS_PROTO.getAuthInternalErrorCode()));
  }

  @Test
  public void testMalformedJsonBody() throws Exception {
    mockWebServer.enqueue(new MockResponse().setBody("{\"abc:123}").setStatus("HTTP/1.1 200 OK"));

    HttpResponse response = postJson(buildJsonHttpRequest(mockWebServer.url("/").toString()));

    assertThat(mockWebServer.getRequestCount()).isEqualTo(1);
    RecordedRequest request = mockWebServer.takeRequest();
    String receivedBody = request.getBody().readUtf8();
    assertThat(receivedBody).isEqualTo(VALID_JSON_REQUEST_BODY);
    assertThat(request.getHeader("Content-Type")).isEqualTo("application/json; charset=utf-8");

    assertThat(response.getStatus().getCode()).isEqualTo(500);
    assertThat(response.getStatus().getMessage()).isEqualTo("invalid response JSON");
    assertThat(response.hasJsonBody()).isFalse();
    assertThat(response.hasProtoBody()).isFalse();
  }

  @Test
  public void testHugeJsonResponse() throws Exception {
    mockWebServer.enqueue(buildHugeJsonMockResponse());

    HttpResponse response = postJson(buildJsonHttpRequest(mockWebServer.url("/").toString()));
    assertThat(mockWebServer.getRequestCount()).isEqualTo(1);
    RecordedRequest request = mockWebServer.takeRequest();
    String receivedBody = request.getBody().readUtf8();
    assertThat(receivedBody).isEqualTo(VALID_JSON_REQUEST_BODY);
    assertThat(request.getHeader("Content-Type")).isEqualTo("application/json; charset=utf-8");

    assertThat(response.getStatus().getCode()).isEqualTo(500);
    assertThat(response.getStatus().getMessage()).isEqualTo("response length exceeds limit of 1MB");
    assertThat(response.hasProtoBody()).isFalse();
    assertThat(response.hasJsonBody()).isFalse();
  }

  @Test
  public void testHugeProtoResponse() throws Exception {
    mockWebServer.enqueue(buildHugeProtoMockResponse());

    HttpResponse response = postJson(buildProtoHttpRequest(mockWebServer.url("/").toString()));
    assertThat(mockWebServer.getRequestCount()).isEqualTo(1);
    RecordedRequest request = mockWebServer.takeRequest();
    assertThat(request.getBody().readByteArray()).isEqualTo(VALID_PROTO_REQUEST_BODY);
    assertThat(request.getHeader("Content-Type")).isEqualTo("application/x-protobuf");

    assertThat(response.getStatus().getCode()).isEqualTo(500);
    assertThat(response.getStatus().getMessage()).isEqualTo("response length exceeds limit of 1MB");
    assertThat(response.hasJsonBody()).isFalse();
    assertThat(response.hasProtoBody()).isFalse();
  }

  @Test
  public void testMalformedJsonErrorBody() throws Exception {
    mockWebServer.enqueue(
        new MockResponse()
            .setBody("This is not JSON.")
            .setStatus("HTTP/1.1 400 Bad Request")
            .addHeader("Content-Type: application/json; charset=utf-8"));

    HttpResponse response = postJson(buildJsonHttpRequest(mockWebServer.url("/").toString()));

    assertThat(mockWebServer.getRequestCount()).isEqualTo(1);
    RecordedRequest request = mockWebServer.takeRequest();
    String receivedBody = request.getBody().readUtf8();
    assertThat(receivedBody).isEqualTo(VALID_JSON_REQUEST_BODY);
    assertThat(request.getHeader("Content-Type")).isEqualTo("application/json; charset=utf-8");

    assertThat(response.getStatus().getCode()).isEqualTo(400);
    assertThat(response.getStatus().getMessage()).isEqualTo("Bad Request");
    assertThat(response.hasProtoBody()).isFalse();
    assertThat(response.hasJsonBody()).isFalse();
  }

  @Test
  public void testMalformedProtoErrorBody() throws Exception {
    mockWebServer.enqueue(
        new MockResponse()
            .setBody("This is not a proto.")
            .setStatus("HTTP/1.1 400 Bad Request")
            .addHeader("Content-Type: application/x-protobuf"));

    HttpResponse response = postJson(buildProtoHttpRequest(mockWebServer.url("/").toString()));

    assertThat(mockWebServer.getRequestCount()).isEqualTo(1);
    RecordedRequest request = mockWebServer.takeRequest();
    assertThat(request.getBody().readByteArray()).isEqualTo(VALID_PROTO_REQUEST_BODY);
    assertThat(request.getHeader("Content-Type")).isEqualTo("application/x-protobuf");

    assertThat(response.getStatus().getCode()).isEqualTo(400);
    assertThat(response.getStatus().getMessage()).isEqualTo("Bad Request");
    assertThat(response.hasJsonBody()).isFalse();
    assertThat(response.hasProtoBody()).isFalse();
  }

  @Test
  public void testCheckGet() throws Exception {
    mockWebServer.enqueue(new MockResponse().setStatus("HTTP/1.1 200 OK"));

    boolean got = checkGet(mockWebServer.url("/").toString());

    assertThat(mockWebServer.getRequestCount()).isEqualTo(1);
    RecordedRequest request = mockWebServer.takeRequest();
    assertThat(request.getMethod()).isEqualTo("GET");
    assertThat(got).isTrue();
  }

  @Test
  public void testCheckGetIpv4() throws Exception {
    mockWebServer.enqueue(new MockResponse().setStatus("HTTP/1.1 200 OK"));

    boolean got = checkGet(mockWebServer.url("/").toString(), AddressFamily.V4);

    assertThat(mockWebServer.getRequestCount()).isEqualTo(0);
    assertThat(got).isFalse();
  }

  @Test
  public void testCheckGetIpv6() throws Exception {
    mockWebServer.enqueue(new MockResponse().setStatus("HTTP/1.1 200 OK"));

    boolean got = checkGet(mockWebServer.url("/").toString(), AddressFamily.V6);

    assertThat(mockWebServer.getRequestCount()).isEqualTo(1);
    RecordedRequest request = mockWebServer.takeRequest();
    assertThat(request.getMethod()).isEqualTo("GET");
    assertThat(got).isTrue();
  }

  @Test
  public void testLookupDns() throws Exception {
    Dns mockDns = (hostname) -> Arrays.asList(address);
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
    // Override the multi-network DNS lookup, since the test framework doesn't support it.
    when(mockNetwork.getAllByName(anyString()))
        .then(invocation -> InetAddress.getAllByName(invocation.getArgument(0)));
    FutureTask<Boolean> future = new FutureTask<>(() -> httpFetcher.checkGet(url, mockNetwork));
    new Thread(future).start();
    return future.get();
  }

  /**
   * Runs a checkGet request in the background and blocks until it returns. This is needed because
   * the synchronous checkGet method cannot be called on the main thread. The IP version used for
   * checkGet can be restricted with addressFamily.
   */
  private boolean checkGet(String url, AddressFamily addressFamily) throws Exception {
    // Override the multi-network DNS lookup, since the test framework doesn't support it.
    when(mockNetwork.getAllByName(anyString()))
        .then(invocation -> InetAddress.getAllByName(invocation.getArgument(0)));
    FutureTask<Boolean> future =
        new FutureTask<>(() -> httpFetcher.checkGet(url, mockNetwork, addressFamily));
    new Thread(future).start();
    return future.get();
  }
}
