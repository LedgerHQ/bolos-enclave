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
#include "BolosSGX_t.h"

#include "machine.h"
#include "portable_msg.h"
#include "portable_persistent_context.h"
#include "portable_transient_context.h"
#include "platform_al.h"
#include "platform_persistent_context.h"
#include "bolos.h"
#include "platform_sgx.h"

#include "include/secp256k1.h"
#include "sodium.h"

#include "sgx_tseal.h"
#include "sgx_tkey_exchange.h"
#include "sgx_trts_exception.h"

extern bolos_transient_context_t bolosTransientContext;

bolos_persistent_context_t persistentContext;
bool exceptionHandlerSet = false;
bool persistentContextSet = false;
bool persistentContextDirty = false;
bool initialized;

extern secp256k1_context *secp256k1Context;

static const uint8_t SP_PUBLIC_KEY[] = {
    0x42, 0xc2, 0xd5, 0xec, 0x83, 0xb3, 0x78, 0x5f, 0x2e, 0xcc, 0xd9,
    0xe1, 0x46, 0x76, 0x96, 0x19, 0x2d, 0xb0, 0xa3, 0x05, 0x15, 0x72,
    0x16, 0xdf, 0x0a, 0x85, 0x1e, 0x09, 0x05, 0x52, 0x06, 0xef, 0xa1,
    0x46, 0x8d, 0x58, 0x38, 0x43, 0x9d, 0x90, 0x6c, 0x23, 0x3f, 0xf0,
    0x1e, 0x8a, 0x01, 0x10, 0xd5, 0x83, 0x30, 0xff, 0xba, 0x1a, 0x61,
    0x76, 0x5e, 0xd3, 0x00, 0xcf, 0xa9, 0xc8, 0x40, 0x98};

static const uint8_t ID_DIV_ATTESTATION[] = {0x01};
static const uint8_t ID_DIV_PERSONALIZATON[] = {0x02};

uint32_t getPersistentContext(uint8_t *context, uint32_t context_size);

int exception_handler(sgx_exception_info_t *exception) {
    return EXCEPTION_CONTINUE_SEARCH;
}

void setExceptionHandler() {
#ifndef SGX_DEBUG
    if (!exceptionHandlerSet) {
        void *result = sgx_register_exception_handler(1, exception_handler);
        exceptionHandlerSet = (result != NULL);
    }
#endif
}

void public_key_to_intel(const unsigned char *x, const unsigned char *y,
                         sgx_ec256_public_t *pub) {
    unsigned int i;
    for (i = 0; i < 32; i++) {
        pub->gx[i] = x[31 - i];
        pub->gy[i] = y[31 - i];
    }
}

sgx_status_t initRA(int openPSESession, sgx_ra_context_t *ra_context) {
    sgx_status_t ret;
    sgx_ec256_public_t publicKey;
    public_key_to_intel(SP_PUBLIC_KEY, SP_PUBLIC_KEY + 32, &publicKey);
    if (openPSESession) {
        int busy_retry_times = 2;
        do {
            ret = sgx_create_pse_session();
        } while (ret == SGX_ERROR_BUSY && busy_retry_times--);
        if (ret != SGX_SUCCESS) {
            return ret;
        }
    }
    ret = sgx_ra_init(&publicKey, openPSESession, ra_context);
    if (openPSESession) {
        sgx_close_pse_session();
    }
    return ret;
}

uint32_t getAttestationKeyRA(sgx_ra_context_t ra_context, int keyIndex,
                             uint8_t *response, uint32_t response_size) {
    bolos_persistent_context_t bolosPersistentContext;
    sgx_ra_key_128_t key128_1;
    uint8_t *keyPointer;
    secp256k1_pubkey pubkey;
    size_t pubkeyLength = 65;
    uint8_t tmp[65];
    uint8_t sealingKey[crypto_secretbox_KEYBYTES];
    uint8_t nonce[crypto_secretbox_NONCEBYTES];
    uint32_t status = 0;

    if (response_size <
        65 + crypto_secretbox_MACBYTES + crypto_secretbox_NONCEBYTES) {
        return 0;
    }

    if (!platform_read_persistent_context(&bolosPersistentContext)) {
        return 0;
    }

    switch (keyIndex) {
    case 1:
        if (bolosPersistentContext.endorsement_private_key1.d_len != 32) {
            return 0;
        }
        keyPointer = bolosPersistentContext.endorsement_private_key1.d;
        break;
    case 2:
        if (bolosPersistentContext.endorsement_private_key2.d_len != 32) {
            return 0;
        }
        keyPointer = bolosPersistentContext.endorsement_private_key2.d;
        break;
    default:
        return 0;
    }

    if (secp256k1_ec_pubkey_create(secp256k1Context, &pubkey, keyPointer) !=
        1) {
        return 0;
    }
    secp256k1_ec_pubkey_serialize(secp256k1Context, tmp, &pubkeyLength, &pubkey,
                                  SECP256K1_EC_UNCOMPRESSED);
    if (sgx_ra_get_keys(ra_context, SGX_RA_KEY_SK, &key128_1) != SGX_SUCCESS) {
        printf("sgx_ra_get_keys_1 failed\n");
        return 0;
    }
    if (!platform_sha256_init() ||
        !platform_sha256_update((uint8_t *)ID_DIV_ATTESTATION,
                                sizeof(ID_DIV_ATTESTATION)) ||
        !platform_sha256_update(key128_1, sizeof(key128_1)) ||
        !platform_sha256_final(sealingKey)) {
        printf("Key diversification failed\n");
        goto error;
    }
    platform_random(nonce, crypto_secretbox_NONCEBYTES);
    if (crypto_secretbox_easy(response + crypto_secretbox_NONCEBYTES, tmp, 65,
                              nonce, sealingKey)) {
        goto error;
    }
    memmove(response, nonce, crypto_secretbox_NONCEBYTES);
    status = 65 + crypto_secretbox_MACBYTES + crypto_secretbox_NONCEBYTES;
error:
    platform_secure_memset0(key128_1, sizeof(sgx_ra_key_128_t));
    platform_secure_memset0(sealingKey, crypto_secretbox_KEYBYTES);
    return status;
}

uint32_t setPersonalizationKeyRA(sgx_ra_context_t ra_context, uint8_t *data,
                                 uint32_t data_size) {
    sgx_ra_key_128_t key128_1;
    uint8_t sealingKey[crypto_secretbox_KEYBYTES];
    uint32_t status = 0;

    if (data_size !=
        crypto_secretbox_KEYBYTES + crypto_secretbox_MACBYTES +
            crypto_secretbox_NONCEBYTES) {
        printf("Invalid data size\n");
        return 0;
    }
    if (!bolosTransientContext.sessionOpened) {
        printf("Session not opened\n");
        return 0;
    }
    if (sgx_ra_get_keys(ra_context, SGX_RA_KEY_SK, &key128_1) != SGX_SUCCESS) {
        printf("sgx_ra_get_keys_1 failed\n");
        return 0;
    }
    if (!platform_sha256_init() ||
        !platform_sha256_update((uint8_t *)ID_DIV_PERSONALIZATON,
                                sizeof(ID_DIV_PERSONALIZATON)) ||
        !platform_sha256_update(key128_1, sizeof(key128_1)) ||
        !platform_sha256_final(sealingKey)) {
        printf("Key diversification failed\n");
        goto error;
    }
    if (crypto_secretbox_open_easy(bolosTransientContext.personalizationKey,
                                   data + crypto_secretbox_NONCEBYTES,
                                   data_size - crypto_secretbox_NONCEBYTES,
                                   data, sealingKey)) {
        printf("Secretbox open failed\n");
        goto error;
    } else {
        bolosTransientContext.personalizationKeySet = 1;
    }

    status = 1;
error:
    platform_secure_memset0(key128_1, sizeof(sgx_ra_key_128_t));
    platform_secure_memset0(sealingKey, crypto_secretbox_KEYBYTES);
    return status;
}

sgx_status_t closeRA(sgx_ra_context_t ra_context) {
    return sgx_ra_close(ra_context);
}

uint32_t createPersistentContext(uint8_t *response, uint32_t response_size) {
    uint32_t result;
    setExceptionHandler();
    persistentContextSet = false;
    platform_secure_memset0(&persistentContext, sizeof(persistentContext));
    platform_random(persistentContext.deviceWrappingKey,
                    sizeof(persistentContext.deviceWrappingKey));
    result = getPersistentContext(response, response_size);
    if (result) {
        persistentContextSet = true;
        if (!initialized) {
            initialized = bolos_init();
        }
    }
    return result;
}

uint32_t setPersistentContext(uint8_t *context, uint32_t context_size) {
    sgx_status_t status;
    uint32_t plainLength = 0;
    uint32_t contextSize = sizeof(bolos_persistent_context_t);
    setExceptionHandler();
    persistentContextSet = false;
    if (context_size < sizeof(sgx_sealed_data_t)) {
        printf("Set persistent context failed (invalid structure)\n");
        return 0;
    }
    status = sgx_unseal_data((sgx_sealed_data_t *)context, NULL, &plainLength,
                             (uint8_t *)&persistentContext, &contextSize);
    if (status != SGX_SUCCESS) {
        printf("Set persistent context failed (decrypt)\n");
        return 0;
    }
    if (contextSize != sizeof(bolos_persistent_context_t)) {
        printf("Set persistent context failed (size)\n");
        return 0;
    }
    if (!initialized) {
        initialized = bolos_init();
    }
    persistentContextSet = true;
    return 1;
}

uint32_t getPersistentContext(uint8_t *context, uint32_t context_size) {
    sgx_status_t status;
    sgx_attributes_t defaultAttributes = {0xfffffffffffffff3L, 0};
    uint8_t *tmp;
    uint32_t sealedSize =
        sgx_calc_sealed_data_size(0, sizeof(bolos_persistent_context_t));
    if (context_size < sealedSize) {
        return 0;
    }
    tmp = (uint8_t *)malloc(sealedSize);
    if (tmp == NULL) {
        return 0;
    }
    status = sgx_seal_data_ex(SGX_KEYPOLICY_MRENCLAVE, defaultAttributes, 0, 0,
                              NULL, sizeof(persistentContext),
                              (uint8_t *)&persistentContext, sealedSize,
                              (sgx_sealed_data_t *)tmp);
    if (status != SGX_SUCCESS) {
        free(tmp);
        return 0;
    }
    memmove(context, tmp, sealedSize);
    free(tmp);
    return sealedSize;
}

uint32_t isPersistentContextDirty() {
    return (persistentContextDirty ? 1 : 0);
}

void clearPersistentContextDirty() {
    persistentContextDirty = false;
}

uint32_t exchange(uint8_t *command, uint32_t command_size, uint8_t *response,
                  uint32_t response_size) {
    bolos_exec_status_t status;
    uint32_t outLength;
    sgx_context_t sgxContext;
    if (!persistentContextSet) {
        return 0;
    }
    sgxContext.responseBuffer = response;
    sgxContext.responseLength = response_size;
    status =
        bolos_handle_message(&sgxContext, command, command_size, &outLength);
    if (status == BOLOS_EXEC_OK) {
        return outLength;
    }
    return 0;
}
