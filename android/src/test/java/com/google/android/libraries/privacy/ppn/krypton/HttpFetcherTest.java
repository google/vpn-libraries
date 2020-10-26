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

import com.squareup.okhttp.mockwebserver.MockResponse;
import com.squareup.okhttp.mockwebserver.MockWebServer;
import com.squareup.okhttp.mockwebserver.RecordedRequest;
import com.squareup.okhttp.mockwebserver.SocketPolicy;
import java.time.Duration;
import org.json.JSONException;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;

/** Unit tests for {@link HttpFetcher}. */
@RunWith(RobolectricTestRunner.class)
public class HttpFetcherTest {

  @Before
  public void setUp() {
    HttpFetcher.setTimeout(Duration.ofSeconds(1));
  }

  private static BoundSocketFactoryFactory getSocketFactoryFactory() {
    return new TestBoundSocketFactoryFactory();
  }

  private static JSONObject buildHttpHeaders() throws JSONException {
    final JSONObject someHeaders = new JSONObject();
    someHeaders.put("header1", "header1_value");
    someHeaders.put("header2", "header2_value");
    return someHeaders;
  }

  private static JSONObject buildJsonBody() throws JSONException {
    final JSONObject message = new JSONObject();
    message.put("oauth_token", "some_token");
    return message;
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

  @Test
  public void testHttp() throws Exception {
    MockWebServer mockWebServer = new MockWebServer();
    mockWebServer.start();
    mockWebServer.enqueue(buildPositiveMockResponse());

    String response =
        new HttpFetcher(getSocketFactoryFactory())
            .postJson(
                mockWebServer.url("/").toString(),
                buildHttpHeaders().toString(),
                buildJsonBody().toString());
    RecordedRequest request = mockWebServer.takeRequest();
    String receivedBody = request.getBody().readUtf8();
    assertThat(receivedBody).isEqualTo(buildJsonBody().toString());
    assertThat(request.getHeader("Content-Type")).isEqualTo("application/json; charset=utf-8");
    JSONObject jsonResponse = new JSONObject(response);
    assertThat(jsonResponse.getJSONObject("status").getInt("code")).isEqualTo(200);

    assertThat(jsonResponse.getJSONObject("json_body").toString())
        .isEqualTo(buildJsonResponse().toString());
    mockWebServer.shutdown();
  }

  @Test
  public void testToInvalidHost() throws Exception {
    String response =
        new HttpFetcher(getSocketFactoryFactory())
            .postJson("http://unknown", buildHttpHeaders().toString(), buildJsonBody().toString());
    JSONObject jsonResponse = new JSONObject(response);
    assertThat(jsonResponse.getJSONObject("status").getInt("code")).isEqualTo(500);
    assertThat(jsonResponse.getJSONObject("status").getString("message"))
        .isEqualTo("IOException executing request");
  }

  @Test
  public void testNegativeResponse() throws Exception {
    MockWebServer mockWebServer = new MockWebServer();
    mockWebServer.start();

    mockWebServer.enqueue(
        new MockResponse().setResponseCode(402).setBody("Something went wrong in the server"));
    String response =
        new HttpFetcher(getSocketFactoryFactory())
            .postJson(
                mockWebServer.url("/").toString(),
                buildHttpHeaders().toString(),
                buildJsonBody().toString());
    RecordedRequest request = mockWebServer.takeRequest();
    String receivedBody = request.getBody().readUtf8();
    assertThat(receivedBody).isEqualTo(buildJsonBody().toString());
    assertThat(request.getHeader("Content-Type")).isEqualTo("application/json; charset=utf-8");
    JSONObject jsonResponse = new JSONObject(response);
    assertThat(jsonResponse.getJSONObject("status").getInt("code")).isEqualTo(402);
    assertThat(jsonResponse.has("json_body")).isFalse();
    mockWebServer.shutdown();
  }

  @Test
  public void testTimeout() throws Exception {
    MockWebServer mockWebServer = new MockWebServer();
    mockWebServer.start();
    mockWebServer.enqueue(new MockResponse().setSocketPolicy(SocketPolicy.NO_RESPONSE));
    String response =
        new HttpFetcher(getSocketFactoryFactory())
            .postJson(
                mockWebServer.url("/").toString(),
                buildHttpHeaders().toString(),
                buildJsonBody().toString());
    RecordedRequest request = mockWebServer.takeRequest();
    String receivedBody = request.getBody().readUtf8();
    assertThat(receivedBody).isEqualTo(buildJsonBody().toString());
    assertThat(request.getHeader("Content-Type")).isEqualTo("application/json; charset=utf-8");
    JSONObject jsonResponse = new JSONObject(response);
    assertThat(jsonResponse.getJSONObject("status").getInt("code")).isEqualTo(500);
    assertThat(jsonResponse.getJSONObject("status").getString("message"))
        .isEqualTo("IOException executing request");
    mockWebServer.shutdown();
  }

  @Test
  public void testEmpty() throws Exception {
    MockWebServer mockWebServer = new MockWebServer();
    mockWebServer.start();
    mockWebServer.enqueue(new MockResponse().setResponseCode(200));
    String response =
        new HttpFetcher(getSocketFactoryFactory())
            .postJson(
                mockWebServer.url("/").toString(),
                buildHttpHeaders().toString(),
                buildJsonBody().toString());
    RecordedRequest request = mockWebServer.takeRequest();
    String receivedBody = request.getBody().readUtf8();
    assertThat(receivedBody).isEqualTo(buildJsonBody().toString());
    assertThat(request.getHeader("Content-Type")).isEqualTo("application/json; charset=utf-8");
    JSONObject jsonResponse = new JSONObject(response);
    assertThat(jsonResponse.getJSONObject("status").getInt("code")).isEqualTo(500);
    assertThat(jsonResponse.getJSONObject("status").getString("message"))
        .isEqualTo("invalid response JSON");
    mockWebServer.shutdown();
  }

  @Test
  public void testMalformedJsonBody() throws Exception {
    MockWebServer mockWebServer = new MockWebServer();
    mockWebServer.start();
    mockWebServer.enqueue(new MockResponse().setBody("{\"abc:123}").setResponseCode(200));
    String response =
        new HttpFetcher(getSocketFactoryFactory())
            .postJson(
                mockWebServer.url("/").toString(),
                buildHttpHeaders().toString(),
                buildJsonBody().toString());
    RecordedRequest request = mockWebServer.takeRequest();
    String receivedBody = request.getBody().readUtf8();
    assertThat(receivedBody).isEqualTo(buildJsonBody().toString());
    assertThat(request.getHeader("Content-Type")).isEqualTo("application/json; charset=utf-8");
    JSONObject jsonResponse = new JSONObject(response);
    assertThat(jsonResponse.getJSONObject("status").getInt("code")).isEqualTo(500);
    assertThat(jsonResponse.getJSONObject("status").getString("message"))
        .isEqualTo("invalid response JSON");
    mockWebServer.shutdown();
  }
}
