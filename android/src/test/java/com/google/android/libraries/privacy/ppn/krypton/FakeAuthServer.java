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

import android.util.Log;
import androidx.annotation.Nullable;
import com.squareup.okhttp.mockwebserver.Dispatcher;
import com.squareup.okhttp.mockwebserver.MockResponse;
import com.squareup.okhttp.mockwebserver.MockWebServer;
import com.squareup.okhttp.mockwebserver.RecordedRequest;
import java.io.IOException;
import java.util.ArrayDeque;
import java.util.Deque;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/** Wrapper around MockWebServer with Auth-specific mocking helpers. */
public class FakeAuthServer {
  private static final String TAG = "FakeAuthServer";

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

  private final Deque<Integer> publicKeyResponseCodes;
  private final Deque<Integer> initialDataResponseCodes;
  private final Deque<Integer> authResponseCodes;

  private MockResponse createPublicKeyResponse(
      RecordedRequest request, @Nullable Integer responseCode) {
    if (responseCode == null) {
      return new MockResponse().setResponseCode(500);
    }

    MockResponse response = new MockResponse().setResponseCode(responseCode);
    // If this is a bad response just return the response
    if (responseCode != 200) {
      return response;
    }

    JSONObject publicKeyResponse = new JSONObject();
    try {
      JSONObject publicKeyRequest = new JSONObject(request.getBody().copy().readUtf8());
      publicKeyResponse.put("pem", PEM);
      if (publicKeyRequest.optBoolean("request_nonce")) {
        publicKeyResponse.put("attestation_nonce", "some_nonce");
      }
    } catch (JSONException e) {
      Log.w(TAG, "Failed processing public key request.", e);
      return new MockResponse().setResponseCode(400);
    }

    response.setBody(publicKeyResponse.toString());
    response.setHeader("Content-Type", "application/json; charset=utf-8");
    return response;
  }

  private MockResponse createInitialDataResponse(@Nullable Integer responseCode) {
    if (responseCode == null) {
      return new MockResponse().setResponseCode(500);
    }

    MockResponse response = new MockResponse().setResponseCode(responseCode);
    // If this is a bad response just return the response
    if (responseCode != 200) {
      return response;
    }

    return response;
  }

  private MockResponse createAuthResponse(@Nullable Integer responseCode) {
    if (responseCode == null) {
      return new MockResponse().setResponseCode(500);
    }

    MockResponse response = new MockResponse().setResponseCode(responseCode);
    // If this is a bad response just return the response
    if (responseCode != 200) {
      return response;
    }

    JSONObject authResponse = new JSONObject();
    try {
      JSONArray blindedTokenSignature = new JSONArray();
      blindedTokenSignature.put("foobarbaz");
      authResponse.put("blinded_token_signature", blindedTokenSignature);
    } catch (JSONException e) {
      Log.w(TAG, "Failed processing auth request.", e);
      return new MockResponse().setResponseCode(400);
    }

    response.setBody(authResponse.toString());
    response.setHeader("Content-Type", "application/json; charset=utf-8");
    return response;
  }

  public FakeAuthServer() {
    mockWebServer = new MockWebServer();
    publicKeyResponseCodes = new ArrayDeque<>();
    initialDataResponseCodes = new ArrayDeque<>();
    authResponseCodes = new ArrayDeque<>();

    final Dispatcher dispatcher =
        new Dispatcher() {
          @Override
          public MockResponse dispatch(RecordedRequest request) throws InterruptedException {
            switch (request.getPath()) {
              case "/public_key_request":
                return createPublicKeyResponse(request, publicKeyResponseCodes.pollFirst());
              case "/initial_data":
                return createInitialDataResponse(initialDataResponseCodes.pollFirst());
              case "/auth":
                return createAuthResponse(authResponseCodes.pollFirst());
              default:
                return new MockResponse().setResponseCode(404);
            }
          }
        };

    mockWebServer.setDispatcher(dispatcher);
  }

  public void start() throws IOException {
    mockWebServer.start();
  }

  public void enqueuePositivePublicKeyResponse() {
    publicKeyResponseCodes.add(200);
  }

  public void enqueuePositiveInitialDataResponse() {
    initialDataResponseCodes.add(200);
  }

  public void enqueuePositiveAuthResponse() {
    authResponseCodes.add(200);
  }

  public void enqueueNegativePublicKeyResponseWithCode(int code) {
    publicKeyResponseCodes.add(code);
  }

  public void enqueueNegativeInitialDataResponseWithCode(int code) {
    initialDataResponseCodes.add(code);
  }

  public void enqueueNegativeAuthResponseWithCode(int code) {
    authResponseCodes.add(code);
  }

  public String publicKeyUrl() {
    return mockWebServer.url("public_key_request").toString();
  }

  public String initialDataUrl() {
    return mockWebServer.url("initial_data").toString();
  }

  public String authUrl() {
    return mockWebServer.url("auth").toString();
  }

  public RecordedRequest takeRequest() throws InterruptedException {
    return mockWebServer.takeRequest();
  }
}
