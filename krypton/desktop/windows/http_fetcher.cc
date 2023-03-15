/*
 * Copyright (C) 2021 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "privacy/net/krypton/desktop/windows/http_fetcher.h"

#include <strsafe.h>
#include <windows.h>
#include <winhttp.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include <optional>
#include <string>

#include "base/logging.h"
#include "privacy/net/krypton/desktop/windows/utils/error.h"
#include "privacy/net/krypton/desktop/windows/utils/strings.h"
#include "privacy/net/krypton/proto/http_fetcher.proto.h"
#include "third_party/absl/cleanup/cleanup.h"
#include "third_party/absl/strings/str_cat.h"
#include "third_party/absl/strings/string_view.h"

namespace privacy {
namespace krypton {
namespace windows {

HttpResponse CreateErrorResponse(absl::string_view description) {
  auto error_status = utils::GetStatusForError(description, GetLastError());
  LOG(ERROR) << error_status;
  HttpResponse response;
  response.mutable_status()->set_code(HTTP_STATUS_SERVER_ERROR);
  response.mutable_status()->set_message(error_status.ToString());
  return response;
}

HttpResponse HttpFetcher::PostJson(const HttpRequest& request) {
  LOG(INFO) << "Calling HttpFetcher postJson Windows method";
  bool json_request = request.has_json_body();

  // From the server URL, we need a hostname, path.
  URL_COMPONENTS url_server_components;
  memset(&url_server_components, 0, sizeof(url_server_components));
  url_server_components.dwStructSize = sizeof(url_server_components);
  url_server_components.dwHostNameLength = -1;
  url_server_components.dwUrlPathLength = -1;
  url_server_components.dwSchemeLength = -1;

  // If dwUrlLength is set to zero, WinHttpCrackUrl assumes that the pwszUrl
  // string is null terminated
  std::wstring url = utils::CharToWstring(request.url());
  if (WinHttpCrackUrl(url.data(), url.size(),
                      /* dwFlags= */ 0, &url_server_components) == 0) {
    return CreateErrorResponse(
        absl::StrCat("WinHttpCrackUrl unable to parse URL: ", request.url()));
  }

  std::wstring hostname{url_server_components.lpszHostName,
                        url_server_components.dwHostNameLength};
  std::wstring url_path{url_server_components.lpszUrlPath,
                        url_server_components.dwUrlPathLength};
  LOG(INFO) << "HttpFetcher hostname: " << utils::WstringToString(hostname);

  // Use WinHttpOpen to obtain a HINTERNET session handle.
  HINTERNET session_handle = WinHttpOpen(
      /* pszAgentW= */ L"PPN HttpFetcher", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
      WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS,
      /* dwFlags= */ 0);
  if (session_handle == nullptr) {
    return CreateErrorResponse("WinHttpOpen failed");
  }
  auto session_handle_cleanup = absl::MakeCleanup(
      [session_handle]() { WinHttpCloseHandle(session_handle); });

  // Use WinHttpConnect to obtain a HINTERNET connect handle.
  HINTERNET connect_handle = WinHttpConnect(
      session_handle, (LPCWSTR)hostname.c_str(), url_server_components.nPort,
      /* dwReserved= */ 0);

  if (connect_handle == nullptr) {
    return CreateErrorResponse("WinHttpConnect failed");
  }
  auto connect_handle_cleanup = absl::MakeCleanup(
      [connect_handle]() { WinHttpCloseHandle(connect_handle); });

  // Use WinHttpOpenRequest to obtain a HINTERNET request handle.
  HINTERNET request_handle = WinHttpOpenRequest(
      connect_handle, /* pwszVerb= */ L"POST", (LPCWSTR)url_path.c_str(),
      /* pwszVersion= */ nullptr, WINHTTP_NO_REFERER,
      WINHTTP_DEFAULT_ACCEPT_TYPES,
      url_server_components.nScheme == INTERNET_SCHEME_HTTPS
          ? WINHTTP_FLAG_SECURE
          : 0);

  if (request_handle == nullptr) {
    return CreateErrorResponse("WinHttpOpenRequest failed");
  }
  auto request_handle_cleanup = absl::MakeCleanup(
      [request_handle]() { WinHttpCloseHandle(request_handle); });

  // Add headers to the request
  const int kHeaderLength = 1024;
  WCHAR headers[kHeaderLength] = L"";
  if (json_request) {
    StringCchCopyW(headers, kHeaderLength,
                   L"Accept: application/json\r\n"
                   L"Content-Type: application/json; charset=utf-8\r\n");
  } else {
    StringCchCopyW(headers, kHeaderLength,
                  L"Content-Type: application/x-protobuf\r\n");
  }

  for (auto const& header : request.headers()) {
    auto cat_result = StringCbCatW(
        headers, kHeaderLength,
        utils::CharToWstring(header.first + ": " + header.second + "\r\n")
            .c_str());
    if (cat_result != S_OK) {
      return CreateErrorResponse("StringCbCatW failed");
    }
  }

  if (WinHttpAddRequestHeaders(request_handle, headers,
                               /* dwHeadersLength= */ -1,
                               WINHTTP_ADDREQ_FLAG_ADD) == 0) {
    return CreateErrorResponse("WinHttpAddRequestHeaders failed");
  }

  std::string post_data =
      json_request ? request.json_body() : request.proto_body();

  if (WinHttpSendRequest(request_handle, WINHTTP_NO_ADDITIONAL_HEADERS,
                         /* dwHeadersLength= */ 0, (LPVOID)post_data.data(),
                         post_data.size(), post_data.size(),
                         /* dwContext= */ 0) == 0) {
    return CreateErrorResponse("WinHttpSendRequest failed");
  }

  if (WinHttpReceiveResponse(request_handle, /* lpReserved= */ nullptr) == 0) {
    return CreateErrorResponse("WinHttpReceiveResponse failed");
  }

  // Query status code and status message
  DWORD status_code = 0;
  DWORD status_code_length = sizeof(status_code);
  WCHAR status_message[128];
  ULONG status_message_length = sizeof(status_message);
  if ((WinHttpQueryHeaders(
           request_handle,
           WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
           /* pwszName= */ nullptr, &status_code, &status_code_length,
           /* lpdwIndex= */ nullptr) == 0) ||
      (WinHttpQueryHeaders(request_handle, WINHTTP_QUERY_STATUS_TEXT,
                           /* pwszName= */ nullptr, &status_message,
                           &status_message_length,
                           /* lpdwIndex= */ nullptr) == 0)) {
    return CreateErrorResponse("WinHttpQueryHeaders failed");
  }

  HttpResponse response;
  response.mutable_status()->set_code(status_code);
  response.mutable_status()->set_message(utils::WcharToString(status_message));

  if (status_code != 200) {
    LOG(ERROR) << "PostJson received status code " << status_code;
    return response;
  }

  // Read response
  std::string post_result;
  DWORD available_data_size = 0;
  while (true) {
    if (WinHttpQueryDataAvailable(request_handle, &available_data_size) == 0) {
      return CreateErrorResponse("WinHttpQueryDataAvailable failed");
    }
    if (available_data_size == 0) break;

    // Allocate space for the buffer.
    std::string temp;
    temp.resize(available_data_size);

    // Read the data.
    DWORD bytes_read = 0;
    if (WinHttpReadData(request_handle, (LPVOID)(&temp[0]), available_data_size,
                        &bytes_read) == 0) {
      return CreateErrorResponse("WinHttpReadData failed");
    }
    if (bytes_read != available_data_size) {
      return CreateErrorResponse("Error reading response");
    }
    post_result += temp;
  }

  LOG(INFO) << "HttpFetcher::PostJson Windows succeeded";
  if (json_request) {
    response.set_json_body(post_result);
  } else {
    response.set_proto_body(post_result);
  }

  return response;
}

absl::StatusOr<std::string> HttpFetcher::LookupDns(
    const std::string& hostname) {
  LOG(INFO) << "Calling HttpFetcher::LookupDns for hostname " << hostname;

  int status;
  ADDRINFOW* result = nullptr;
  ADDRINFOW hints;
  ZeroMemory(&hints, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  status = GetAddrInfoW(utils::CharToWstring(hostname).c_str(),
                        /*service*/ nullptr, &hints, &result);
  if (status != 0) {
    return utils::GetStatusForError("GetAddrInfoW failed", WSAGetLastError());
  }

  if (result == nullptr) {
    return absl::NotFoundError(
        absl::StrCat("Cannot convert host to IP address: ", hostname));
  }
  auto addr_info_cleanup =
      absl::MakeCleanup([result]() { FreeAddrInfoW(result); });

  // The max length for IPv6 is long enough for either IPv4 or IPv6.
  wchar_t ipstringbuffer[INET6_ADDRSTRLEN];
  status = GetNameInfoW((LPSOCKADDR)result->ai_addr, (DWORD)result->ai_addrlen,
                        ipstringbuffer, (DWORD)INET6_ADDRSTRLEN,
                        /*service=*/nullptr, 0, NI_NUMERICHOST);
  if (status != 0) {
    return utils::GetStatusForError("GetNameInfoW failed", WSAGetLastError());
  }

  return utils::WcharToString(ipstringbuffer);
}

}  // namespace windows
}  // namespace krypton
}  // namespace privacy
