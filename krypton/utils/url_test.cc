#include "privacy/net/krypton/utils/url.h"

#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"

namespace privacy {
namespace krypton {
namespace utils {

namespace {
class URLTest : public ::testing::Test {};
}  // namespace

TEST_F(URLTest, TestURLEncodeNoParams) {
  URL url("https://www.test");
  ASSERT_EQ(url.AssembleString(), "https://www.test");
}

TEST_F(URLTest, TestURLEncodeWithEscapableParams) {
  URL url("https://www.test");
  url.AddQueryComponent("query1", "qvalue1");
  url.AddQueryComponent("query2", "");
  url.AddQueryComponent("", "skipped");
  url.AddQueryComponent("query 3", "value with spaces");
  url.AddQueryComponent("query4", " ");
  url.AddQueryComponent("query5", "  with   multiple  spaces ");
  ASSERT_EQ(url.AssembleString(),
            "https://"
            "www.test?query1=qvalue1&query2=&query%203=value%20with%20spaces"
            "&query4=%20&query5=%20%20with%20%20%20multiple%20%20spaces%20");
}

TEST_F(URLTest, TestURLEncodeSymbols) {
  URL url("https://www.test");
  url.AddQueryComponent("q", "!@#$%^&*=+[]{}");
  ASSERT_EQ(url.AssembleString(),
            "https://www.test?q=%21%40%23%24%25%5E%26%2A%3D%2B%5B%5D%7B%7D");
}

}  // namespace utils
}  // namespace krypton
}  // namespace privacy
