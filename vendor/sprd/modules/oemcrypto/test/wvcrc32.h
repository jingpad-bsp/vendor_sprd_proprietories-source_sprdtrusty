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
 * wvcrc32.h
 *
 * Compute CRC32 Checksum. Needed for verification of WV Keybox.
 */

#ifndef CDM_WVCRC32_H_
#define CDM_WVCRC32_H_

#include <stdint.h>

namespace wvoec {

uint32_t wvcrc32(const uint8_t* p_begin, int i_count);
uint32_t wvcrc32Init();
uint32_t wvcrc32Cont(const uint8_t* p_begin, int i_count, uint32_t prev_crc);

// Convert to network byte order
uint32_t wvcrc32n(const uint8_t* p_begin, int i_count);

}  // namespace wvoec

#endif  // CDM_WVCRC32_H_
