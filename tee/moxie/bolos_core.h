/*******************************************************************************
*   BOLOS Enclave
*   (c) 2017 Ledger
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/

#ifndef __BOLOS_CORE_H__
#define __BOLOS_CORE_H__

struct bls_area_s {
    uint8_t WIDE *buffer;
    size_t length;
};
typedef struct bls_area_s bls_area_t;

void bls_set_return(const void *addr, size_t length);
size_t bls_copy_input_parameters(const uint8_t *parameters, uint32_t offset,
                                 size_t parametersLength);
uint32_t bls_check_api_level(void);

#endif // __BOLOS_CORE_H__
