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

#ifndef __PLATFORM_AL_H__

#define __PLATFORM_AL_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

void platform_secure_memset0(void *buffer, uint32_t length);
bool platform_random(uint8_t *buffer, uint32_t length);
bool platform_sha256_init(void);
bool platform_sha256_update(uint8_t *buffer, uint32_t length);
bool platform_sha256_final(uint8_t *target);
uint8_t *platform_get_reply_buffer(void *platformContext, uint32_t *size);
uint32_t platform_get_id(uint8_t *buffer, uint32_t length);
bool platform_verify_id(uint8_t *buffer, uint32_t length);
uint32_t platform_get_version_string(uint8_t *buffer, uint32_t length);
void platform_printc(char ch);

#endif
