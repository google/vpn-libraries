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

#include "privacy/net/krypton/utils/looper.h"

#include <memory>
#include <thread>

#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"
#include "third_party/absl/status/status.h"

namespace privacy {
namespace krypton {
namespace utils {
namespace {

class LooperTest : public ::testing::Test {};

TEST_F(LooperTest, ThreadTest) {
  LooperThread thread("Test Looper");
  bool called = false;

  EXPECT_TRUE(thread.Post([&called] { called = true; }));
  thread.Stop();
  thread.Join();

  ASSERT_TRUE(called);
}

TEST_F(LooperTest, GetCurrentLooperTest) {
  LooperThread thread("Test Looper");
  LooperThread *captured_looper = nullptr;

  EXPECT_EQ(LooperThread::GetCurrentLooper(), nullptr);

  EXPECT_TRUE(thread.Post([&captured_looper] {
    captured_looper = LooperThread::GetCurrentLooper();
  }));
  thread.Stop();
  thread.Join();

  EXPECT_EQ(captured_looper, &thread);
}

TEST_F(LooperTest, ClosureAddsClosureTest) {
  LooperThread thread("Test Looper");
  bool called = false;

  EXPECT_TRUE(thread.Post([&thread, &called] {
    // Add a new closure that sets the value later.
    thread.Post([&called] { called = true; });
    thread.Stop();
  }));

  thread.Join();

  ASSERT_TRUE(called);
}

TEST_F(LooperTest, PostAfterStopFails) {
  LooperThread thread("Test Looper");

  thread.Stop();
  EXPECT_FALSE(thread.Post([] {}));
}

TEST_F(LooperTest, CleanupTest) {
  auto thread = std::make_unique<LooperThread>("Test Looper");
  bool called = false;

  std::thread::id post_thread_id;
  std::thread::id cleanup_thread_id;

  thread->Post(
      [&post_thread_id] { post_thread_id = std::this_thread::get_id(); });
  thread->AddCleanupHandler([&called, &cleanup_thread_id] {
    called = true;
    cleanup_thread_id = std::this_thread::get_id();
  });

  thread->Stop();
  thread->Join();

  ASSERT_TRUE(called);
  ASSERT_EQ(post_thread_id, cleanup_thread_id);
}

}  // namespace
}  // namespace utils
}  // namespace krypton
}  // namespace privacy
