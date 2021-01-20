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

import com.google.android.libraries.privacy.ppn.internal.json.Json;
import com.squareup.okhttp.mockwebserver.MockResponse;
import com.squareup.okhttp.mockwebserver.MockWebServer;
import com.squareup.okhttp.mockwebserver.RecordedRequest;
import java.io.IOException;
import org.json.JSONArray;
import org.json.JSONObject;

/** Wrapper around MockWebServer with Brass-specific mocking helpers. */
public class MockBrass {
  private final MockWebServer mockWebServer;

  private static JSONObject buildJsonResponse() {
    JSONObject userPrivateIp = new JSONObject();
    Json.put(userPrivateIp, "ipv4_range", "10.2.2.123/32");
    Json.put(userPrivateIp, "ipv6_range", "fec2:0001::3/64");

    JSONArray userPrivateIpArray = new JSONArray();
    userPrivateIpArray.put(userPrivateIp);

    JSONArray egressPointSockAddrs = new JSONArray();
    egressPointSockAddrs.put("64.9.240.165:2153");
    egressPointSockAddrs.put("[2604:ca00:f001:4::5]:2153");

    JSONObject ppnDataPlane = new JSONObject();
    Json.put(ppnDataPlane, "user_private_ip", userPrivateIpArray);
    Json.put(ppnDataPlane, "egress_point_sock_addr", egressPointSockAddrs);
    Json.put(
        ppnDataPlane, "egress_point_public_value", "a22j+91TxHtS5qa625KCD5ybsyzPR1wkTDWHV2qSQQc=");
    Json.put(ppnDataPlane, "server_nonce", "Uzt2lEzyvZYzjLAP3E+dAA==");
    Json.put(ppnDataPlane, "uplink_spi", 123);
    Json.put(ppnDataPlane, "expiry", "2020-08-07T01:06:13+00:00");

    JSONObject body = new JSONObject();
    Json.put(body, "ppn_dataplane", ppnDataPlane);
    return body;
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
