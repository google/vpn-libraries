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

import com.squareup.okhttp.mockwebserver.MockResponse;
import com.squareup.okhttp.mockwebserver.MockWebServer;
import com.squareup.okhttp.mockwebserver.RecordedRequest;
import java.io.IOException;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/** Wrapper around MockWebServer with Brass-specific mocking helpers. */
public class MockBrass {
  private final MockWebServer mockWebServer;

  private static JSONObject buildJsonResponse() {
    final JSONObject jsonContent = new JSONObject();
    try {
      JSONObject bridge = new JSONObject();
      bridge.put("session_id", 1234);
      // Session, Crypto keys are are base64 encoded. The values are from a test run from a test
      // only GAIA account and are safe to commit.
      bridge.put("session_token", "AGAVvIZS9kvlqEeNvLc0Vy6R6/jbiAY5mQ==");
      bridge.put("client_crypto_key", "Dv4I+/Uw38Yty/agJ8R0/A==");
      bridge.put("server_crypto_key", "WlqNik4vuOqYjgbkOsHFAQ==");
      JSONArray ipRangeArray = new JSONArray();
      ipRangeArray.put("192.168.0.1");
      bridge.put("ip_ranges", ipRangeArray);

      JSONArray dataplaneArray = new JSONArray();
      dataplaneArray.put("192.168.0.2:2153");
      bridge.put("data_plane_sock_addrs", dataplaneArray);
      bridge.put("control_plane_sock_addrs", dataplaneArray);

      jsonContent.put("bridge", bridge);
    } catch (JSONException impossible) {
      // It's not actually possible for putting a string in a JSONObject to throw this.
      throw new AssertionError(impossible);
    }
    return jsonContent;
  }

  /** Returns a MockResponse that simulates Brass successfully adding an egress. */
  private static MockResponse buildPositiveResponse() {
    // mock a simple response with the JSON Content
    MockResponse response = new MockResponse();
    JSONObject jsonContent = buildJsonResponse();
    response.setBody(jsonContent.toString());
    response.setHeader("Content-Type", "application/json; charset=utf-8");
    return response;
  }

  public void enqueueNegativeResponseWithCode(int code, String body) {
    mockWebServer.enqueue(new MockResponse().setResponseCode(code).setBody(body));
  }

  public MockBrass() {
    mockWebServer = new MockWebServer();
  }

  public void start() throws IOException {
    mockWebServer.start();
  }

  public void enqueuePositiveResponse() {
    mockWebServer.enqueue(buildPositiveResponse());
  }

  /** Returns the url for clients to use when connecting to this Brass instance. */
  public String url() {
    return mockWebServer.url("addegress").toString();
  }

  public RecordedRequest takeRequest() throws InterruptedException {
    return mockWebServer.takeRequest();
  }
}
