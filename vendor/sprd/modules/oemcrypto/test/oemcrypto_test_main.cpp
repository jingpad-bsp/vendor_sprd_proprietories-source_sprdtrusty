/*
 * Copyright (c) 2019, Spreadtrum Communications.
 *
 * The above copyright notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * oemcrypto_test_main.cpp
 *
 * To support OEMCrypto unit test.
 */

#include <gtest/gtest.h>
#include <iostream>

#include "OEMCryptoCENC.h"
#include "log.h"
#include "oec_device_features.h"

static void acknowledge_cast() {
  std::cout
      << "==================================================================\n"
      << "= This device is expected to load x509 certs as a cast receiver. =\n"
      << "==================================================================\n";
}

// This special main procedure is used instead of the standard GTest main,
// because we need to initialize the list of features supported by the device.
// Also, the test filter is updated based on the feature list.
int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  wvcdm::g_cutoff = wvcdm::LOG_INFO;
  bool is_cast_receiver = false;
  bool force_load_test_keybox = false;
  bool filter_tests = true;
  for (int i = 0; i < argc; i++) {
    if (!strcmp(argv[i], "--cast")) {
      acknowledge_cast();
      is_cast_receiver = true;
    }
    if (!strcmp(argv[i], "--force_load_test_keybox")) {
      force_load_test_keybox = true;
    }
    if (!strcmp(argv[i], "--no_filter")) {
      filter_tests = false;
    }
  }
  wvoec::global_features.Initialize(is_cast_receiver, force_load_test_keybox);
  // If the user requests --no_filter, we don't change the filter, otherwise, we
  // filter out features that are not supported.
  if (filter_tests) {
    ::testing::GTEST_FLAG(filter) =
        wvoec::global_features.RestrictFilter(::testing::GTEST_FLAG(filter));
  }
  return RUN_ALL_TESTS();
}
