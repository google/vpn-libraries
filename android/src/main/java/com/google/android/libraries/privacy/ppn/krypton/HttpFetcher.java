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

import android.util.Log;
import androidx.annotation.Nullable;
import com.google.android.libraries.privacy.ppn.internal.json.Json;
import com.google.android.libraries.privacy.ppn.xenon.PpnNetwork;
import com.google.common.annotations.VisibleForTesting;
import java.io.IOException;
import java.time.Duration;
import java.util.Iterator;
import okhttp3.CacheControl;
import okhttp3.Call;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * Provides utilities to the Krypton Native library to fetch URL connection. Parameters of the
 * request are in JSON string format.
 */
public class HttpFetcher {
  private static final String TAG = "HttpFetcher";
  private static final String JSON_CONTENT_TYPE = "application/json; charset=utf-8";
  // TODO: Timeout should be customizable.
  private static Duration requestTimeout = Duration.ofSeconds(30);

  private final BoundSocketFactoryFactory socketFactory;

  public HttpFetcher(BoundSocketFactoryFactory socketFactory) {
    this.socketFactory = socketFactory;
  }

  /** Sets timeout for the request, use it only for testing */
  @VisibleForTesting
  static void setTimeout(Duration duration) {
    requestTimeout = duration;
  }

  /**
   * Builds the POST request based on the JSON parameters.
   *
   * @throws JSONException if either of the JSON Strings is malformed.
   */
  static Request buildPostRequest(String url, @Nullable String headers, String jsonBody)
      throws JSONException {
    Request.Builder reqBuilder = getGenericRequestBuilder(url, headers);

    JSONObject jsonBodyObject = new JSONObject(jsonBody);
    // Put the body as a mime.
    reqBuilder.post(
        RequestBody.create(MediaType.parse(JSON_CONTENT_TYPE), jsonBodyObject.toString()));
    return reqBuilder.build();
  }

  /**
   * Builds the GET request based on the parameters that is used for checkGet.
   *
   * @throws JSONException if any JSON Strings are maltformed.
   */
  static Request buildCheckGetRequest(String url, @Nullable String headers) throws JSONException {
    Request.Builder reqBuilder = getGenericRequestBuilder(url, headers);
    // For checkGet request, we want to make sure these calls are not Cached.
    reqBuilder.cacheControl(CacheControl.FORCE_NETWORK);
    reqBuilder.get();
    return reqBuilder.build();
  }

  private static Request.Builder getGenericRequestBuilder(String url, @Nullable String headers)
      throws JSONException {
    Request.Builder reqBuilder = new Request.Builder();

    reqBuilder.url(url);

    // Add the headers
    if (headers != null && !headers.isEmpty()) {
      JSONObject httpHeaders = new JSONObject(headers);

      Iterator<String> keys = httpHeaders.keys();
      while (keys.hasNext()) {
        String key = keys.next();
        reqBuilder.addHeader(key, httpHeaders.getString(key));
      }
    } else {
      Log.i(TAG, "Request has no HTTP headers");
    }

    return reqBuilder;
  }

  /**
   * Performs a GET request to the given URL on the given network and verifies it is successful. It
   * only checks whether the response was successful or not, aka response code [200, 300). This is a
   * synchronous API and is blocking.
   */
  public boolean checkGet(String url, @Nullable String headers, PpnNetwork ppnNetwork) {
    Log.w(TAG, "HTTP GET (checkGet) to " + url);
    Request req;
    try {
      req = buildCheckGetRequest(url, headers);
    } catch (JSONException e) {
      // The malformed headers could have sensitive info, so don't log the Exception itself.
      Log.w(TAG, "GET (checkGet) has malformed headers; returning false.");
      return false;
    }

    OkHttpClient.Builder builder = new OkHttpClient().newBuilder();
    OkHttpClient client =
        builder
            // Set the timeout to be a very short time period for checkGet calls.
            .callTimeout(Duration.ofSeconds(1))
            .socketFactory(socketFactory.withNetwork(ppnNetwork))
            .build();
    Call call = client.newCall(req);

    Response response;
    try {
      response = call.execute();
    } catch (IOException e) {
      // It should be safe to log an IOException.
      Log.w(TAG, "GET (checkGet) failed; returning false.", e);
      return false;
    }

    // Whether the response has response code [200, 300).
    boolean success = response.isSuccessful();
    response.close();
    return success;
  }

  JSONObject buildHttpResponseJson(int code, String message) {
    JSONObject jsonResponse = new JSONObject();
    JSONObject http = new JSONObject();
    Json.put(jsonResponse, "status", http);
    Json.put(http, "code", code);
    Json.put(http, "message", message);
    return jsonResponse;
  }

  // Post request that sends MIME of JSON and expects a JSON response.
  // On failure, timeout or any other unknown failures, A response JSON is constructed and send to
  // the caller.
  // This is a synchronous API and is blocking.
  public String postJson(String url, @Nullable String headers, String jsonBody) {
    Log.w(TAG, "HTTP POST to " + url);

    Request req;
    try {
      req = buildPostRequest(url, headers, jsonBody);
    } catch (JSONException e) {
      // The malformed request JSON may have sensitive info, so don't log it.
      Log.w(TAG, "POST request has invalid JSON.");
      return buildHttpResponseJson(400, "invalid request JSON").toString();
    }

    OkHttpClient.Builder builder = new OkHttpClient().newBuilder();
    OkHttpClient client =
        builder
            .callTimeout(requestTimeout)
            .socketFactory(socketFactory.withCurrentNetwork())
            .build();
    Call call = client.newCall(req);

    Response response;
    try {
      response = call.execute();
    } catch (IOException e) {
      // The failed request may have sensitive info, so don't log it.
      Log.w(TAG, "Failed to POST JSON request.");
      return buildHttpResponseJson(500, "IOException executing request").toString();
    }

    // Construct a response that starts with the http response.
    JSONObject jsonResponse = buildHttpResponseJson(response.code(), response.message());

    // Only try to read the body if the response is OK.
    if (response.code() != 200) {
      response.body().close();
      return jsonResponse.toString();
    }

    // Read the response body.
    String body;
    try {
      body = response.body().string();
    } catch (IOException e) {
      // The failed response may have sensitive info, so don't log it.
      Log.w(TAG, "Failed to read POST response body.");
      return buildHttpResponseJson(500, "IOException reading response body").toString();
    }

    // Parse the response body as JSON.
    JSONObject message;
    try {
      message = new JSONObject(body);
    } catch (JSONException e) {
      // The failed response may have sensitive info, so don't log it.
      Log.w(TAG, "Response body has malformed JSON.");
      return buildHttpResponseJson(500, "invalid response JSON").toString();
    }

    Json.put(jsonResponse, "json_body", message);
    return jsonResponse.toString();
  }
}
