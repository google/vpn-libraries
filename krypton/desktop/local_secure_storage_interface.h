#ifndef PRIVACY_NET_KRYPTON_DESKTOP_LOCAL_SECURE_STORAGE_INTERFACE_H_
#define PRIVACY_NET_KRYPTON_DESKTOP_LOCAL_SECURE_STORAGE_INTERFACE_H_

#include <string>

#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"

class LocalSecureStorageInterface {
 public:
  virtual ~LocalSecureStorageInterface() = default;

  // Stores a kv-pair into local storage.
  virtual absl::Status StoreData(absl::string_view key,
                                 absl::string_view value) = 0;

  // Retrieves a value based on a key from local storage.
  virtual absl::StatusOr<std::string> FetchData(absl::string_view key) = 0;

  // Deletes a kv-pair from local storage.
  virtual absl::Status DeleteData(absl::string_view key) = 0;
};

#endif  // PRIVACY_NET_KRYPTON_DESKTOP_LOCAL_SECURE_STORAGE_INTERFACE_H_
