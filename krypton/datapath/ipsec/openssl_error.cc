// Copyright 2021 Google LLC
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

#include "privacy/net/krypton/datapath/ipsec/openssl_error.h"

#include "third_party/absl/strings/substitute.h"
#include "third_party/absl/types/optional.h"
#include "third_party/openssl/err.h"

namespace privacy {
namespace krypton {
namespace datapath {
namespace ipsec {

// Returns the next error on the error stack, if there is one.
absl::optional<std::string> GetOneOpenSSLError() {
  const char *file, *data;
  int line, flags;
  auto code = ERR_get_error_line_data(&file, &line, &data, &flags);
  if (code == 0) {
    return absl::nullopt;
  }

  char buffer[1024];
  ERR_error_string_n(code, buffer, sizeof(buffer));

  std::string details;
  if ((data != nullptr) && ((flags & ERR_FLAG_STRING) == ERR_FLAG_STRING)) {
    details = data;
  }

  return absl::Substitute("OpenSSL error: $0:$1: $2: $3", file, line, buffer,
                          details);
}

absl::Status GetOpenSSLError(absl::string_view prefix) {
  std::vector<std::string> errors;
  absl::optional<std::string> error;
  while ((error = GetOneOpenSSLError())) {
    errors.push_back(*error);
  }
  std::string message = absl::StrJoin(errors, "\n");

  return absl::InternalError(absl::StrCat(prefix, ": ", message));
}

}  // namespace ipsec
}  // namespace datapath
}  // namespace krypton
}  // namespace privacy
