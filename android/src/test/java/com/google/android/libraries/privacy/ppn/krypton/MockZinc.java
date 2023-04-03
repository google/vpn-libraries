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

package com.google.android.libraries.privacy.ppn.krypton;

import com.google.common.collect.ImmutableList;
import com.squareup.okhttp.mockwebserver.MockResponse;
import com.squareup.okhttp.mockwebserver.MockWebServer;
import com.squareup.okhttp.mockwebserver.RecordedRequest;
import java.io.IOException;
import java.util.Optional;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/** Wrapper around MockWebServer with Zinc-specific mocking helpers. */
public class MockZinc {
  // A hard-coded key just for tests.
  private static final String PEM =
      "-----BEGIN PUBLIC KEY-----\n"
          + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv90Xf/NN1lRGBofJQzJf\n"
          + "lHvo6GAf25GGQGaMmD9T1ZP71CCbJ69lGIS/6akFBg6ECEHGM2EZ4WFLCdr5byUq\n"
          + "GCf4mY4WuOn+AcwzwAoDz9ASIFcQOoPclO7JYdfo2SOaumumdb5S/7FkKJ70TGYW\n"
          + "j9aTOYWsCcaojbjGDY/JEXz3BSRIngcgOvXBmV1JokcJ/LsrJD263WE9iUknZDhB\n"
          + "K7y4ChjHNqL8yJcw/D8xLNiJtIyuxiZ00p/lOVUInr8C/a2C1UGCgEGuXZAEGAdO\n"
          + "NVez52n5TLvQP3hRd4MTi7YvfhezRcA4aXyIDOv+TYi4p+OVTYQ+FMbkgoWBm5bq\n"
          + "wQIDAQAB\n"
          + "-----END PUBLIC KEY-----\n";

  private final MockWebServer mockWebServer;

  private static JSONObject buildJsonPublicKeyResponse(Optional<String> nonce) {
    JSONObject jsonContent = new JSONObject();
    try {
      jsonContent.put("pem", PEM);
      if (nonce.isPresent()) {
        jsonContent.put("attestation_nonce", nonce.get());
      }
    } catch (JSONException impossible) {
      // It's not actually possible for putting a string in a JSONObject to throw this.
      throw new AssertionError(impossible);
    }
    return jsonContent;
  }

  /** Returns a MockResponse that simulates Zinc successfully approving authentication. */
  private static MockResponse buildPositivePublicKeyResponse(Optional<String> nonce) {
    // mock a simple response with the JSON Content
    MockResponse response = new MockResponse();
    JSONObject jsonContent = buildJsonPublicKeyResponse(nonce);
    response.setBody(jsonContent.toString());
    response.setHeader("Content-Type", "application/json; charset=utf-8");
    return response;
  }

  private static JSONObject buildJsonAuthResponse() {
    JSONObject jsonContent = new JSONObject();
    try {
      // "foobarbaz" can be verified with the PEM above.
      jsonContent.put("blinded_token_signature", new JSONArray(ImmutableList.of("foobarbaz")));
    } catch (JSONException impossible) {
      // It's not actually possible for putting a string in a JSONObject to throw this.
      throw new AssertionError(impossible);
    }
    return jsonContent;
  }

  /** Returns a MockResponse that simulates Zinc successfully approving authentication. */
  private static MockResponse buildPositiveAuthResponse() {
    // mock a simple response with the JSON Content
    MockResponse response = new MockResponse();
    JSONObject jsonContent = buildJsonAuthResponse();
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

  public void enqueuePositivePublicKeyResponse() {
    enqueuePositivePublicKeyResponse(Optional.empty());
  }

  public void enqueuePositivePublicKeyResponse(Optional<String> nonce) {
    mockWebServer.enqueue(buildPositivePublicKeyResponse(nonce));
  }

  public void enqueuePositiveAuthResponse() {
    mockWebServer.enqueue(buildPositiveAuthResponse());
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
