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
 * @brief Shared memory API providing a common zone for applications to keep
 * persistent private data in a session
 * @file bolos_sharedmemory.h
 * @author Ledger Firmware Team <hello@ledger.fr>
 * @version 1.0
 * @date 4th of December 2016
 *
 * The shared memory API provides a small transient storage area for all
 * applications that isn't shared with the host.
 * It can be used to implement basic anti replay mechanisms when the anti replay
 * API is not available
 *
 */

#ifndef __BOLOS_SHAREDMEMORY_H__
#define __BOLOS_SHAREDMEMORY_H__

/**
 * @brief Get the size of the shared memory area
 *
 * @return size of the shared memory area
 */

int bls_sharedmemory_get_size(void);

/**
 * @brief Read data from the shared memory area
 * @param [out] parameters buffer to store the data
 * @param [in] offset offset to start reading the data from
 * @param [in] parametersLength length of data to read
 * @return size of parameters copied
 */
size_t bls_sharedmemory_read(const uint8_t *parameters, uint32_t offset,
                             size_t parametersLength);

/**
 * @brief Write data to the shared memory area
 * @param [out] parameters buffer containing the data
 * @param [in] offset offset to start writing the data to
 * @param [in] parametersLength length of data to write
 * @return size of parameters copied
 */
size_t bls_sharedmemory_write(const uint8_t *parameters, uint32_t offset,
                              size_t parametersLength);

#endif // __BOLOS_SHAREDMEMORY_H__
