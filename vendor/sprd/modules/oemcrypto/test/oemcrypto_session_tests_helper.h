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
 * oemcrypto_session_tests_helper.h
 *
 * To support OEMCrypto unit test.
 */

#include <assert.h>
#include <algorithm>
#include <iostream>
#include <openssl/aes.h>
#include <openssl/rand.h>

#include "oec_session_util.h"
#include "oec_test_data.h"
#include "OEMCryptoCENC.h"

namespace wvoec {

class SessionUtil {
public:
  SessionUtil()
      : encoded_rsa_key_(kTestRSAPKCS8PrivateKeyInfo2_2048,
                         kTestRSAPKCS8PrivateKeyInfo2_2048 +
                             sizeof(kTestRSAPKCS8PrivateKeyInfo2_2048)) {}

  // If force is true, we assert that the key loads successfully.
  void CreateWrappedRSAKeyFromKeybox(uint32_t allowed_schemes, bool force);

  // If force is true, we assert that the key loads successfully.
  void CreateWrappedRSAKeyFromOEMCert(uint32_t allowed_schemes, bool force);

  // If force is true, we assert that the key loads successfully.
  void CreateWrappedRSAKey(uint32_t allowed_schemes, bool force);

  // This is used to force installation of a keybox.  This overwrites the
  // production keybox -- it does NOT use OEMCrypto_LoadTestKeybox.
  void InstallKeybox(const wvoec::WidevineKeybox& keybox, bool good);

  // This loads the test keybox or the test RSA key, using LoadTestKeybox or
  // LoadTestRSAKey as needed.
  void EnsureTestKeys();

  void InstallTestSessionKeys(Session* s);

  std::vector<uint8_t> encoded_rsa_key_;
  std::vector<uint8_t> wrapped_rsa_key_;
  wvoec::WidevineKeybox keybox_;
};

}  // namespace wvoec
