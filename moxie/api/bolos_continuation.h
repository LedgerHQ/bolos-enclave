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
 * @brief Continuation API
 * @file bolos_continuation.h
 * @author Ledger Firmware Team <hello@ledger.fr>
 * @version 1.0
 * @date 6th of March 2017
 *
 * The continuation API provides a transparent interruption of the running
 * proccess, exchanging data with the Normal World before resuming.
 *
 * Support of this API is platform dependent
 *
 */

#ifndef __BOLOS_CONTINUATION_H__
#define __BOLOS_CONTINUATION_H__

/**
 * @brief Check if continuation API is supported on this platform
 *
 * @return 1 if supported, 0 if not supported
 */
int bls_continuation_supported(void);

/**
 * @brief Interrupt the current execution, exchanging data with the Normal World
 * and resuming with data available as Normal World input parameters
 *
 * @param [in] addr the buffer containing the data to return
 * @param [in] length length of the data to return
 */
void bls_set_continuation(const void *addr, size_t length);

#endif // __BOLOS_CONTINUATION_H__
