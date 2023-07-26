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

import static java.util.concurrent.TimeUnit.MILLISECONDS;

import android.net.Network;
import android.util.Log;
import androidx.annotation.Nullable;
import com.google.android.gms.tasks.Task;
import com.google.android.gms.tasks.TaskCompletionSource;
import com.google.android.gms.tasks.Tasks;
import com.google.android.libraries.privacy.ppn.internal.HttpRequest;
import com.google.android.libraries.privacy.ppn.internal.HttpResponse;
import com.google.android.libraries.privacy.ppn.internal.HttpStatus;
import com.google.android.libraries.privacy.ppn.internal.NetworkInfo.AddressFamily;
import com.google.common.annotations.VisibleForTesting;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeoutException;
import javax.net.SocketFactory;
import okhttp3.CacheControl;
import okhttp3.Call;
import okhttp3.Callback;
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
  private static final String PROTO_CONTENT_TYPE = "application/x-protobuf";

  // The overall timeout for POST requests.
  private Duration requestTimeout = Duration.ofSeconds(30);
  // The overall timeout for GET requests.
  private static final Duration CHECK_GET_TIMEOUT = Duration.ofSeconds(2);
  // Additional time before stopping a request if okhttp fails to enforce timeouts.
  private static final Duration FALLBACK_TIMEOUT = Duration.ofSeconds(1);
  // Timeout to use for DNS before trying to fall back to the cache.
  // This should be less than the request timeouts to guarantee that we still have time to use the
  // cached value.
  public static final Duration DNS_CACHE_TIMEOUT = Duration.ofSeconds(1);
  // Additional time to give the DNS lookup to succeed after we've tried the cache. This can be
  // longer than the overall request timeout, and we'll keep DNS lookup going in the background so
  // that it can be cached for next time.
  public static final Duration DNS_LOOKUP_TIMEOUT = Duration.ofSeconds(30);

  // A default DNS implementation provided by okhttp3.
  public static final Dns DEFAULT_DNS =
      new Dns() {
        @Override
        public List<InetAddress> lookup(String s) throws UnknownHostException {
          return Dns.SYSTEM.lookup(s);
        }
      };

  // The DNS provider to use.
  private Dns dns = DEFAULT_DNS;

  private final BoundSocketFactoryFactory socketFactory;

  public HttpFetcher(BoundSocketFactoryFactory socketFactory) {
    this.socketFactory = socketFactory;
    this.dns = DEFAULT_DNS;
  }

  public HttpFetcher(BoundSocketFactoryFactory socketFactory, Dns dnsProvider) {
    this.socketFactory = socketFactory;
    this.dns = dnsProvider;
  }

  /** Sets timeout for the request, use it only for testing */
  @VisibleForTesting
  void setTimeout(Duration duration) {
    this.requestTimeout = duration;
  }

  /** Sets the DNS provider to use for requests. Only for testing. */
  @VisibleForTesting
  void setDns(Dns dns) {
    this.dns = dns;
  }

  /**
   * Builds the POST request based on the JSON parameters.
   *
   * @throws JSONException if either of the JSON Strings is malformed.
   */
  static Request buildPostRequest(HttpRequest request) throws JSONException {
    Request.Builder reqBuilder = getGenericRequestBuilder(request);

    if (request.hasProtoBody()) {
      MediaType contentType = MediaType.parse(PROTO_CONTENT_TYPE);
      byte[] protoBytes = request.getProtoBody().toByteArray();
      reqBuilder.post(RequestBody.create(contentType, protoBytes));
    } else {
      JSONObject jsonBodyObject = new JSONObject(request.getJsonBody());
      reqBuilder.post(
          RequestBody.create(MediaType.parse(JSON_CONTENT_TYPE), jsonBodyObject.toString()));
    }

    return reqBuilder.build();
  }

  /**
   * Builds the GET request based on the parameters that is used for checkGet.
   *
   * @throws JSONException if any JSON Strings are malformed.
   */
  static Request buildCheckGetRequest(String url) throws JSONException {
    HttpRequest proto = HttpRequest.newBuilder().setUrl(url).build();

    Request.Builder reqBuilder = getGenericRequestBuilder(proto);
    // For checkGet request, we want to make sure these calls are not Cached.
    reqBuilder.cacheControl(CacheControl.FORCE_NETWORK);
    reqBuilder.get();
    return reqBuilder.build();
  }

  private static Request.Builder getGenericRequestBuilder(HttpRequest request) {
    Request.Builder reqBuilder = new Request.Builder();

    reqBuilder.url(request.getUrl());

    // Add the headers.
    for (Map.Entry<String, String> header : request.getHeadersMap().entrySet()) {
      reqBuilder.addHeader(header.getKey(), header.getValue());
    }

    return reqBuilder;
  }

  /**
   * Performs a GET request to the given URL on the given network and verifies it is successful. It
   * only checks whether the response was successful or not, aka response code [200, 300). This is a
   * synchronous API and is blocking. The address family used for the check can be controlled with
   * the addressFamily argument.
   */
  public boolean checkGet(String url, Network ppnNetwork, AddressFamily addressFamily) {
    Log.w(TAG, "HTTP GET (checkGet) to " + url + " (" + addressFamily.name() + ")");
    Request req;
    try {
      req = buildCheckGetRequest(url);
    } catch (JSONException e) {
      // The malformed headers could have sensitive info, so don't log the Exception itself.
      Log.w(TAG, "GET (checkGet) has malformed headers; returning false.");
      return false;
    }

    // Set the timeout to be a very short time period for checkGet calls.
    HttpResponse response =
        doRequest(req, CHECK_GET_TIMEOUT, false, Optional.of(ppnNetwork), addressFamily);

    // Whether the response has response code [200, 300).
    int status = response.getStatus().getCode();
    return status >= 200 && status < 300;
  }

  /**
   * Performs a GET request to the given URL on the given network and verifies it is successful. It
   * only checks whether the response was successful or not, aka response code [200, 300). This is a
   * synchronous API and is blocking.
   */
  public boolean checkGet(String url, Network ppnNetwork) {
    return checkGet(url, ppnNetwork, AddressFamily.V4V6);
  }

  HttpResponse buildHttpResponse(int code, String message) {
    return HttpResponse.newBuilder()
        .setStatus(HttpStatus.newBuilder().setCode(code).setMessage(message).build())
        .build();
  }

  /**
   * Executes the given encoded HttpRequest proto as a POST and returns an encoded HttpResponse
   * proto once the request is complete. The HttpResponse's HTTP status will indicate success or
   * failure.
   */
  public byte[] postJson(byte[] requestBytes) {
    HttpRequest request = null;
    try {
      request = HttpRequest.parseFrom(requestBytes, ExtensionRegistryLite.getEmptyRegistry());
    } catch (InvalidProtocolBufferException e) {
      return buildHttpResponse(400, "invalid request proto").toByteArray();
    }
    return postJson(request).toByteArray();
  }

  /**
   * Executes the given HttpRequest as a POST and returns an HttpResponse once the request is
   * complete. The HttpResponse's HTTP status will indicate success or failure.
   */
  public HttpResponse postJson(HttpRequest request) {
    Log.w(TAG, "HTTP POST to " + request.getUrl());

    Request req;
    try {
      req = buildPostRequest(request);
    } catch (JSONException e) {
      // The malformed request JSON may have sensitive info, so don't log it.
      Log.w(TAG, "POST request has invalid JSON.");
      return buildHttpResponse(400, "invalid request JSON");
    }

    return doRequest(req, requestTimeout, true, Optional.empty());
  }

  /**
   * Executes the given okhttp Request synchronously and returns an HttpResponse once the request is
   * complete. The HttpResponse's HTTP status will indicate success or failure.
   *
   * @param request the okhttp request to perform.
   * @param timeout the call timeout to use for okhttp.
   * @param parseJsonBody whether to try to parse the body as JSON and validate it.
   * @param network optional network to perform the request on. If empty, uses the current network.
   */
  private HttpResponse doRequest(
      Request request,
      Duration timeout,
      boolean parseJsonBody,
      Optional<Network> network,
      AddressFamily addressFamily) {
    try {
      // Add a higher-level timeout to the await, in case okhttp's timeout fails.
      Duration awaitTimeout = timeout.plus(FALLBACK_TIMEOUT);
      return Tasks.await(
          doRequestAsync(request, timeout, parseJsonBody, network, addressFamily),
          awaitTimeout.toMillis(),
          MILLISECONDS);
    } catch (TimeoutException e) {
      Log.w(TAG, "http request timed out.");
      return buildHttpResponse(504, "request timed out");
    } catch (InterruptedException e) {
      Log.w(TAG, "Unable to enqueue http request.");
      return buildHttpResponse(500, "http request was interrupted");
    } catch (Exception e) {
      // This should ideally not happen, but it's a catch-all in case we missed some exception.
      Log.w(TAG, "Unable to enqueue http request.");
      return buildHttpResponse(500, "http request failed");
    }
  }

  /**
   * Executes the given okhttp Request synchronously and returns an HttpResponse once the request is
   * complete. The HttpResponse's HTTP status will indicate success or failure.
   *
   * @param request the okhttp request to perform.
   * @param timeout the call timeout to use for okhttp.
   * @param parseJsonBody whether to try to parse the body as JSON and validate it.
   * @param network optional network to perform the request on. If empty, uses the current network.
   */
  private HttpResponse doRequest(
      Request request, Duration timeout, boolean parseJsonBody, Optional<Network> network) {
    return doRequest(request, timeout, parseJsonBody, network, AddressFamily.V4V6);
  }

  /**
   * Executes the given okhttp Request asynchronously and returns a Task that will be resolved with
   * a result once the request is complete. The task should never fail. If the request failed, the
   * task will be completed with an HttpResponse whose HTTP status will indicate success or failure.
   *
   * @param request the okhttp request to perform.
   * @param timeout the call timeout to use for okhttp.
   * @param parseJsonBody whether to try to parse the body as JSON and validate it.
   * @param network optional network to perform the request on. If empty, uses the current network.
   * @param addressFamily Address family to use for the request.
   */
  private Task<HttpResponse> doRequestAsync(
      Request request,
      Duration timeout,
      boolean parseJsonBody,
      Optional<Network> network,
      AddressFamily addressFamily) {
    SocketFactory factory =
        network.isPresent()
            ? socketFactory.withNetwork(network.get())
            : socketFactory.withCurrentNetwork();

    OkHttpClient.Builder builder = new OkHttpClient().newBuilder();
    Dns requestDns = dns;
    if (network.isPresent()) {
      requestDns = new NetworkBoundDns(network.get(), addressFamily);
    }
    OkHttpClient client =
        builder.callTimeout(timeout).dns(requestDns).socketFactory(factory).build();
    Call call = client.newCall(request);

    TaskCompletionSource<HttpResponse> tcs = new TaskCompletionSource<>();

    call.enqueue(
        new Callback() {
          @Override
          public void onFailure(Call call, IOException e) {
            // The failed request may have sensitive info, so don't log it.
            Log.w(TAG, "Failed http request.", e);
            tcs.setResult(buildHttpResponse(500, "IOException executing request"));
          }

          @Override
          public void onResponse(Call call, Response response) {
            // Construct a response that starts with the http response.
            HttpResponse.Builder responseBuilder =
                HttpResponse.newBuilder()
                    .setStatus(
                        HttpStatus.newBuilder()
                            .setCode(response.code())
                            .setMessage(response.message())
                            .build());

            // Only try to read the body if the response is OK.
            if (response.code() != 200) {
              response.body().close();
              tcs.setResult(responseBuilder.build());
              return;
            }

            // Response with missing Content-Type header will be treated as JSON
            String header = response.header("Content-Type");
            if (header != null && header.equals(PROTO_CONTENT_TYPE)) {
              try {
                ByteString bytes = ByteString.readFrom(response.body().byteStream());
                responseBuilder.setProtoBody(bytes);
              } catch (IOException e) {
                // The failed response may have sensitive info, so don't log it.
                Log.w(TAG, "Failed to read http proto response body.", e);
                tcs.setResult(buildHttpResponse(500, "IOException reading response body bytes"));
                return;
              }
            } else {
              // Assume anything else is JSON, for backwards compatibility.

              // Read the response body.
              String body;
              try {
                body = response.body().string();
              } catch (IOException e) {
                // The failed response may have sensitive info, so don't log it.
                Log.w(TAG, "Failed to read http response body string.", e);
                tcs.setResult(buildHttpResponse(500, "IOException reading response body"));
                return;
              }

              // Limit response length to 1 MB before JSON parsing.
              if (body.length() > 1024 * 1024) {
                Log.w(TAG, "Response body length exceeds limit of 1MB.");
                tcs.setResult(buildHttpResponse(500, "response length exceeds limit of 1MB"));
                return;
              }

              if (parseJsonBody) {
                // Parse the response body as JSON.
                JSONObject message;
                try {
                  message = new JSONObject(body);
                } catch (JSONException e) {
                  // The failed response may have sensitive info, so don't log it.
                  Log.w(TAG, "Response body has malformed JSON.");
                  tcs.setResult(buildHttpResponse(500, "invalid response JSON"));
                  return;
                }
                responseBuilder.setJsonBody(message.toString());
              }
            }

            tcs.setResult(responseBuilder.build());
          }
        });

    return tcs.getTask();
  }

  @Nullable
  public String lookupDns(String hostname) {
    try {
      List<InetAddress> addresses = dns.lookup(hostname);
      if (addresses.size() < 1) {
        return null;
      }

      // Prefer IPv4 addresses.
      for (InetAddress address : addresses) {
        if (address instanceof Inet4Address) {
          return address.getHostAddress();
        }
      }

      // If there was no IPv4 address, use the first one.
      return addresses.get(0).getHostAddress();

    } catch (UnknownHostException e) {
      Log.w(TAG, "Failed to look up DNS for " + hostname, e);
      return null;
    }
  }
}
