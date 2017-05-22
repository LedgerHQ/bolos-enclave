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
 * @brief Secure time API used to provide a trusted time reference
 * @file bolos_time.h
 * @author Ledger Firmware Team <hello@ledger.fr>
 * @version 1.0
 * @date 4th of December 2016
 *
 * The time API provides access to a hardware based secure time source.
 *
 * Support of this API is platform dependent
 *
 */

#ifndef __BOLOS_TIME_H__
#define __BOLOS_TIME_H__

/**
 * @brief Check if time hardware APIs are supported on this platform
 *
 * @return 1 if supported, 0 if not supported
 */
int bls_time_supported(void);

/**
 * @brief Return the time difference in seconds between two calls
 *
 * @param [in, out] referenceOut
 *   Buffer to contain the time reference or containing the first time reference
 *
 * @param [in] referenceOutLength
 *   Size of the buffer to contain the time reference
 *
 * @param [out] delta
 *   Time difference in seconds between two calls for the same reference
 *
 * @param [out] trusted
 *   Set to 1 if the time delta is trusted, or 0
 *
 * @return size of the time reference if success, 0 if error
 */
int bls_time_delta(uint8_t *referenceOut, size_t referenceOutLength,
                   uint64_t *delta, uint8_t *trusted);

/**
 * @brief Return the time as the number of seconds since the Epoch, 1970-01-01
 * 00:00:00 +0000 (UTC).
 *
 * @param [out] time
 *   Unix time
 *
 * @param [out] trusted
 *   Set to 1 if the time delta is trusted, or 0
 *
 * @return 1 if success, 0 if error
 */
int bls_time(uint64_t *time, uint8_t *trusted);

#endif // __BOLOS_TIME_H__
