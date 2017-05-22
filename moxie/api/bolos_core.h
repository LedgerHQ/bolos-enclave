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
 * @brief BOLOS Input/Output for the TEE
 * @file bolos_core.h
 * @author Ledger Firmware Team <hello@ledger.fr>
 * @version 1.0
 * @date 29th of February 2016
 *
 * Allow executed code to retrieve parameters and return results
 *
 * This API is TEE / stateless device specific
 */

#ifndef __BOLOS_CORE_H__
#define __BOLOS_CORE_H__

/**
 * @struct bls_area_s
 * @brief Describe a buffer and length data structure
 */
struct bls_area_s {
    uint8_t WIDE *buffer;
    size_t length;
};
typedef struct bls_area_s bls_area_t;

/**
 * @brief send a result back to Normal World
 *
 * @param [in] addr the buffer containing the data to return
 * @param [in] length length of the data to return
 */
void bls_set_return(const void *addr, size_t length);

/**
 * @brief get the available size of Normal World input parameters
 * @return size of input parameters
 */
size_t bls_get_input_parameters_length(void);

/**
 * @brief copy Normal World parameters to the executed code
 * @param [out] parameters buffer containing the parameter value
 * @param [in] offset offset to start copying the Normal World input parameters
 * from
 * @param [in] parametersLength length of Normal World input parameters to copy
 * @return size of parameters copied
 */
size_t bls_copy_input_parameters(const uint8_t *parameters, uint32_t offset,
                                 size_t parametersLength);

/**
 * @brief get the current API level
 * @return API level
 */
uint32_t bls_check_api_level(void);

/**
 * @brief halt executed code
 * @param [in] status exit status (discarded)
 */
void _exit(uint32_t status);

#endif // __BOLOS_CORE_H__
