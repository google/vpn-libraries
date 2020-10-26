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
import org.json.JSONException;
import org.json.JSONObject;

/** Wrapper around MockWebServer with Zinc-specific mocking helpers. */
public class MockZinc {
  private final MockWebServer mockWebServer;

  private static JSONObject buildJsonResponse() {
    JSONObject jsonContent = new JSONObject();
    try {
      jsonContent.put("jwt_token", "some_token");
    } catch (JSONException impossible) {
      // It's not actually possible for putting a string in a JSONObject to throw this.
      throw new AssertionError(impossible);
    }
    return jsonContent;
  }

  /** Returns a MockResponse that simulates Zinc successfully approving authentication. */
  private static MockResponse buildPositiveResponse() {
    // mock a simple response with the JSON Content
    MockResponse response = new MockResponse();
    JSONObject jsonContent = buildJsonResponse();
    response.setBody(jsonContent.toString());
    response.setHeader("Content-Type", "application/json; charset=utf-8");
    return response;
  }

  public MockZinc() {
    mockWebServer = new MockWebServer();
  }

  public void start() throws IOException {
    mockWebServer.start();
  }

  public void enqueuePositiveResponse() {
    mockWebServer.enqueue(buildPositiveResponse());
  }

  public void enqueueNegativeResponseWithCode(int code, String body) {
    mockWebServer.enqueue(new MockResponse().setResponseCode(code).setBody(body));
  }

  /** Returns the url for clients to use when connecting to this Zinc instance. */
  public String url() {
    return mockWebServer.url("auth").toString();
  }

  public RecordedRequest takeRequest() throws InterruptedException {
    return mockWebServer.takeRequest();
  }
}
