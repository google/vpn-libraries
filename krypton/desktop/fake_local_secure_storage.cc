#include "privacy/net/krypton/desktop/fake_local_secure_storage.h"

#include <iostream>
#include <map>
#include <string>

#include "third_party/absl/status/status.h"

namespace privacy {
namespace krypton {
namespace desktop {

absl::Status FakeLocalSecureStorage::StoreData(absl::string_view key,
                                               absl::string_view value) {
  store_[key] = value;
  return absl::OkStatus();
}

absl::StatusOr<std::string> FakeLocalSecureStorage::FetchData(
    absl::string_view key) {
  if (store_[key].empty()) {
    return absl::NotFoundError("Value not found for key: " + std::string(key));
  }
  return std::string(store_[key]);
}

absl::Status FakeLocalSecureStorage::DeleteData(absl::string_view key) {
  store_.erase(key);
  return absl::OkStatus();
}

}  // namespace desktop
}  // namespace krypton
}  // namespace privacy
