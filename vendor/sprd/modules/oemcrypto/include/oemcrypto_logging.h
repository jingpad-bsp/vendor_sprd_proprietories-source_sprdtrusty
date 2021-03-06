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
 */

#ifndef WVOEC_OEMCRYPTO_LOGGING_H_
#define WVOEC_OEMCRYPTO_LOGGING_H_

#include <iostream>
#include <string>

#include "log.h"
#include "OEMCryptoCENC.h"

namespace wvoec_unisoc {

// The constants below represent integers with a single "on" bit that
// represents categories of logging This allows users to specify with
// more precision what they want to log. LogCategoryEnabled(category)
// is used to see if the category passed in the parameters is to
// be logged based on the current settings. Categories can be combines
// using the | (or) bitwise  operator. For example
// LogCategoryEnabled(category1 | category2)  will return true if
// category1 and/or category2 are set to logging.

const int kLoggingTraceOEMCryptoCalls = 0x01;
const int kLoggingDumpContentKeys = 0x02;
const int kLoggingDumpKeyControlBlocks = 0x04;
const int kLoggingDumpDerivedKeys = 0x08;
const int kLoggingTraceNonce = 0x10;
const int kLoggingTraceDecryption = 0x20;
const int kLoggingTraceUsageTable = 0x40;
const int kLoggingDumpTraceAll = 0xFF;

void SetLoggingSettings(int level, int categories);

// set level of logging
void SetLoggingLevel(int level);

void TurnOffLoggingForAllCategories();

// Returns true if the category passed is set to logging.
// Returns false otherwise. The category constant declared
// above are passed.
bool LogCategoryEnabled(int category);

// Turn on logging  for the categories passed.
void AddLoggingForCategories(int categories);

// Turn off logging for the categories passed.
void RemoveLoggingForCategories(int categories);

void dump_hex_helper(std::string& buffer, std::string name,
                     const uint8_t* vector, size_t length);

void dump_hex(std::string name, const uint8_t* vector, size_t length);

void dump_array_part_helper(std::string& buffer, std::string array,
                            size_t index, std::string name,
                            const uint8_t* vector, size_t length);

void dump_array_part(std::string array, size_t index,
                     std::string name, const uint8_t* vector, size_t length);

}  // namespace wvoec_unisoc

#endif

