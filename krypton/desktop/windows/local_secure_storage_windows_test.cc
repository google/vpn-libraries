/*
 * Copyright (C) 2022 Google Inc.
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

#include "privacy/net/krypton/desktop/windows/local_secure_storage_windows.h"

#include <memory>
#include <string>

#include "privacy/net/krypton/desktop/local_secure_storage_interface.h"
#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"

namespace privacy {
namespace krypton {
namespace desktop {

using testing::status::IsOkAndHolds;

class LocalSecureStorageWindowsTest : public ::testing::Test {
  void SetUp() override {
    storage_ = std::make_unique<LocalSecureStorageWindows>();
  }

 protected:
  std::unique_ptr<LocalSecureStorageInterface> storage_;
};

TEST_F(LocalSecureStorageWindowsTest, TestStoreFetch) {
  std::string key = "dataKey";
  std::string value = "secureValue";
  ASSERT_OK(storage_->StoreData(key, value));
  ASSERT_THAT(storage_->FetchData(key), IsOkAndHolds(value));
}

TEST_F(LocalSecureStorageWindowsTest, TestFetchAfterDeleteFailure) {
  std::string key = "dataKey";
  std::string value = "secureValue";
  ASSERT_OK(storage_->StoreData(key, value));
  ASSERT_THAT(storage_->FetchData(key), IsOkAndHolds(value));
  ASSERT_OK(storage_->DeleteData(key));
  ASSERT_FALSE(storage_->FetchData(key).ok());
}

}  // namespace desktop
}  // namespace krypton
}  // namespace privacy
