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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "bolos.h"
#include "platform_simu.h"
#include "platform_al.h"
#include "crypto_hash_sha256.h"

static uint8_t IDENTITY_SIMU[] = "SIMU";

crypto_hash_sha256_state sha256;

void platform_assert(int expression) {
    if (!expression) {
        abort();
    }
}

bool platform_random(uint8_t *buffer, uint32_t length) {
    uint32_t i;
    for (i = 0; i < length; i++) {
        buffer[i] = rand();
    }
    return true;
}

bool platform_sha256_init() {
    crypto_hash_sha256_init(&sha256);
    return true;
}

bool platform_sha256_update(uint8_t *buffer, uint32_t length) {
    crypto_hash_sha256_update(&sha256, buffer, length);
    return true;
}

bool platform_sha256_final(uint8_t *target) {
    crypto_hash_sha256_final(&sha256, target);
    return true;
}

uint8_t *platform_get_reply_buffer(void *platformContext, uint32_t *size) {
    simu_context_t *simuContext = (simu_context_t *)platformContext;
    if (size == NULL) {
        return NULL;
    }
    *size = simuContext->responseLength;
    return simuContext->responseBuffer;
}

uint32_t platform_get_id(uint8_t *buffer, uint32_t length) {
    if (length < sizeof(IDENTITY_SIMU)) {
        return 0;
    }
    memmove(buffer, IDENTITY_SIMU, sizeof(IDENTITY_SIMU));
    return sizeof(IDENTITY_SIMU);
}

bool platform_verify_id(uint8_t *buffer, uint32_t length) {
    if (length != sizeof(IDENTITY_SIMU)) {
        return false;
    }
    if (memcmp(buffer, IDENTITY_SIMU, sizeof(IDENTITY_SIMU)) != 0) {
        return false;
    }
    return true;
}

uint32_t platform_get_version_string(uint8_t *buffer, uint32_t length) {
    if (length < 4) {
        return 0;
    }
    buffer[0] = BOLOS_MAJOR_VERSION;
    buffer[1] = BOLOS_MINOR_VERSION;
    buffer[2] = BOLOS_PATCH_VERSION;
    buffer[3] = 0x00;

    return 4;
}

void platform_printc(char ch) {
    printf("%c", ch);
}

void platform_secure_memset0(void *buffer, uint32_t length) {
    memset(buffer, 0, length);
}
