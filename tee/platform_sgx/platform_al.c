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
#include "platform_sgx.h"
#include "platform_al.h"
#include "sgx_tcrypto.h"
#include "sgx_trts.h"
#include "sgx_tseal.h"
#include "BolosSGX_t.h"

sgx_sha_state_handle_t shaHandle = NULL;

static uint8_t IDENTITY_BLOB[] = "PLATFORM_ID";

void platform_assert(int expression) {
    if (!expression) {
        abort();
    }
}

bool platform_random(uint8_t *buffer, uint32_t length) {
    sgx_status_t status;

    status = sgx_read_rand(buffer, length);
    platform_assert(status == SGX_SUCCESS);
    return true;
}

bool platform_sha256_init() {
    sgx_status_t status;

    if (shaHandle != NULL) {
        sgx_sha256_close(shaHandle);
        shaHandle = NULL;
    }
    status = sgx_sha256_init(&shaHandle);
    if (status != SGX_SUCCESS) {
        return false;
    }
    return true;
}

bool platform_sha256_update(uint8_t *buffer, uint32_t length) {
    sgx_status_t status;

    if (shaHandle == NULL) {
        return false;
    }
    status = sgx_sha256_update(buffer, length, shaHandle);
    if (status != SGX_SUCCESS) {
        return false;
    }
    return true;
}

bool platform_sha256_final(uint8_t *target) {
    sgx_status_t status;
    sgx_sha256_hash_t hash;

    if (shaHandle == NULL) {
        return false;
    }
    status = sgx_sha256_get_hash(shaHandle, &hash);
    if (status != SGX_SUCCESS) {
        return false;
    }
    memmove(target, hash, 32);

    return true;
}

uint8_t *platform_get_reply_buffer(void *platformContext, uint32_t *size) {
    sgx_context_t *sgxContext = (sgx_context_t *)platformContext;
    if (size == NULL) {
        return NULL;
    }
    *size = sgxContext->responseLength;
    return sgxContext->responseBuffer;
}

uint32_t platform_get_id(uint8_t *buffer, uint32_t length) {
    sgx_status_t status;
    sgx_attributes_t defaultAttributes = {0xfffffffffffffff3L, 0};
    uint32_t sealedSize = sgx_calc_sealed_data_size(0, sizeof(IDENTITY_BLOB));
    if (length < sealedSize) {
        return 0;
    }
    status = sgx_seal_data_ex(SGX_KEYPOLICY_MRENCLAVE, defaultAttributes, 0, 0,
                              NULL, sizeof(IDENTITY_BLOB), IDENTITY_BLOB,
                              sealedSize, (sgx_sealed_data_t *)buffer);
    if (status != SGX_SUCCESS) {
        return 0;
    }
    return sealedSize;
}

bool platform_verify_id(uint8_t *buffer, uint32_t length) {
    sgx_status_t status;
    uint8_t error = 0;
    uint32_t plainLength = 0;
    uint8_t tmp[sizeof(IDENTITY_BLOB)];
    uint32_t idSize = sizeof(IDENTITY_BLOB);
    if (length < sizeof(sgx_sealed_data_t)) {
        return false;
    }
    status = sgx_unseal_data((sgx_sealed_data_t *)buffer, NULL, &plainLength,
                             tmp, &idSize);
    if (status != SGX_SUCCESS) {
        return false;
    }
    if (idSize != sizeof(IDENTITY_BLOB)) {
        return false;
    }
    while (idSize--) {
        error |= tmp[idSize] ^ IDENTITY_BLOB[idSize];
    }
    if (idSize != 0xffffffff) {
        return false;
    }
    return (error ? false : true);
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
    debugChar(ch);
}

void platform_secure_memset0(void *buffer, uint32_t length) {
    memset_s(buffer, length, 0, length);
}
