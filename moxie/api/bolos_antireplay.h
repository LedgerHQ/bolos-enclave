/*
*******************************************************************************
*   BOLOS TEE
*   (c) 2016, 2017 Ledger
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*   Unless required by applicable law or agreed to in writing, software
*   distributed under the License is distributed on an "AS IS" BASIS,
*   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*   limitations under the License.
********************************************************************************/

/**
 * @brief Anti replay API used to avoid reuse of formerly generated
 * cryptographic material when supported by the platform
 * @file bolos_antireplay.h
 * @author Ledger Firmware Team <hello@ledger.fr>
 * @version 1.0
 * @date 4th of December 2016
 *
 * The anti replay API provides access to hardware based monotonic counters that
 * can be increased and compared against
 * a given value.
 *
 * Support of this API is platform dependent
 *
 */

#ifndef __BOLOS_ANTIREPLAY_H__
#define __BOLOS_ANTIREPLAY_H__

/**
 * @brief Check if antireplay hardware APIs are supported on this platform
 *
 * @return 1 if supported, 0 if not supported
 */
int bls_antireplay_supported(void);

/**
 * @brief Create a new anti-replay counter
 *
 * @param [out] out
 *   Buffer to contain the counter reference used in future calls
 *
 * @param [in] outLength
 *   Size of the buffer to contain the counter reference
 *
 * @return size of the created reference if success, 0 if error
 */
int bls_antireplay_create(uint8_t *referenceOut, size_t referenceOutLength);

/**
 * @brief Query the value of an anti-replay counter
 *
 * @param [in] reference
 *   Buffer containing the counter reference
 *
 * @param [in] referenceLength
 *   Size of the counter reference
 *
 * @param [out] value
 *    Returned value of the counter
 *
 * @return 1 if success, 0 if error
 */
int bls_antireplay_query(uint8_t *reference, size_t referenceLength,
                         uint32_t *value);

/**
 * @brief Increase the value of an anti-replay counter
 *
 * @param [in] reference
 *   Buffer containing the counter reference
 *
 * @param [in] referenceLength
 *   Size of the counter reference
 *
 * @return 1 if success, 0 if error
 */
int bls_antireplay_increase(uint8_t *reference, size_t referenceLength);

/**
 * @brief Delete a previously created anti-replay counter
 *
 * @param [in] reference
 *   Buffer containing the counter reference
 *
 * @param [in] referenceLength
 *   Size of the counter reference
 *
 * @return 1 if success, 0 if error
 */
int bls_antireplay_delete(uint8_t *reference, size_t referenceLength);

#endif // __BOLOS_ANTIREPLAY_H__
