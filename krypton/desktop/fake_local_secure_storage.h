#ifndef PRIVACY_NET_KRYPTON_DESKTOP_FAKE_LOCAL_SECURE_STORAGE_H_
#define PRIVACY_NET_KRYPTON_DESKTOP_FAKE_LOCAL_SECURE_STORAGE_H_

#include <map>
#include <string>

#include "privacy/net/krypton/desktop/local_secure_storage_interface.h"
#include "third_party/absl/status/status.h"

namespace privacy {
namespace krypton {
namespace desktop {

class FakeLocalSecureStorage : public LocalSecureStorageInterface {
 public:
  absl::Status StoreData(absl::string_view key,
                         absl::string_view value) override;
  absl::StatusOr<std::string> FetchData(absl::string_view key) override;
  absl::Status DeleteData(absl::string_view key) override;

 private:
  std::map<absl::string_view, absl::string_view> store_{};
};

}  // namespace desktop
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_DESKTOP_FAKE_LOCAL_SECURE_STORAGE_H_
