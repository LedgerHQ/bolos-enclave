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
#include "bolos.h"
#include "machine.h"

#include "sodium.h"

#include "machine.h"
#include "portable_msg.h"
#include "portable_persistent_context.h"
#include "portable_transient_context.h"
#include "signal.h"

#include "moxie_swi_common.h"
#include "bolos_core.h"
#include "bolos_crypto_common.h"
#include "bolos_wrapping.h"
#include "platform_al.h"
#include "platform_persistent_context.h"

extern bolos_transient_context_t bolosTransientContext;

/*
* bls_wrap
* $r0 -- scope bls_wrapping_scope_t
* $r1 -- in uint8_t*
* $r2 -- length size_t
* $r3 -- out uint8_t*
* $r4 -- outLength size_t
* Output:
* unsigned int
*/
void moxie_bls_wrap(struct machine *mach) {
    uint32_t scope = mach->cpu.regs[MOXIE_R0];
    uint8_t *src;
    uint32_t srcLength = mach->cpu.regs[MOXIE_R2];
    uint8_t *dest;
    uint32_t destLength = mach->cpu.regs[MOXIE_R4];
    uint32_t status = 0;
    uint8_t nonce[crypto_secretbox_NONCEBYTES];
    uint8_t *key;
    uint8_t tmpKey[crypto_secretbox_KEYBYTES];
    bolos_persistent_context_t bolosPersistentContext;

    if (destLength <
        srcLength + crypto_secretbox_MACBYTES + crypto_secretbox_NONCEBYTES) {
        printf("Output buffer length too small\n");
        goto end;
    }
    src = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R1], srcLength,
                                    false);
    if (src == NULL) {
        printf("Invalid input buffer\n");
        goto end;
    }
    dest = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R3], destLength,
                                     false);
    if (dest == NULL) {
        printf("Invalid output buffer\n");
        goto end;
    }

    switch (scope) {
    case BLS_SCOPE_DEVICE:
        if (!platform_read_persistent_context(&bolosPersistentContext)) {
            printf("Failed to read persistent context\n");
            goto end;
        }
        key = bolosPersistentContext.deviceWrappingKey;
        break;
    case BLS_SCOPE_APPLICATION: {
        if (!platform_read_persistent_context(&bolosPersistentContext)) {
            printf("Failed to read persistent context\n");
            goto end;
        }
        if (!platform_sha256_init() ||
            !platform_sha256_update(
                bolosPersistentContext.deviceWrappingKey,
                sizeof(bolosPersistentContext.deviceWrappingKey)) ||
            !platform_sha256_update(
                bolosTransientContext.runningExecCodeHash,
                sizeof(bolosTransientContext.runningExecCodeHash)) ||
            !platform_sha256_final(tmpKey)) {
            printf("Diversification failed\n");
            goto end;
        }
        key = tmpKey;
    } break;
    case BLS_SCOPE_SESSION:
        key = bolosTransientContext.sessionWrappingKey;
        break;
    case BLS_SCOPE_SESSION_APPLICATION: {
        if (!platform_sha256_init() ||
            !platform_sha256_update(
                bolosTransientContext.sessionWrappingKey,
                sizeof(bolosTransientContext.sessionWrappingKey)) ||
            !platform_sha256_update(
                bolosTransientContext.runningExecCodeHash,
                sizeof(bolosTransientContext.runningExecCodeHash)) ||
            !platform_sha256_final(tmpKey)) {
            printf("Diversification failed\n");
            goto end;
        }
        key = tmpKey;
    } break;

    default:
        printf("Unsupported scope\n");
        goto end;
    }
    platform_random(nonce, sizeof(nonce));
    if (crypto_secretbox_easy(dest + crypto_secretbox_NONCEBYTES, src,
                              srcLength, nonce, key)) {
        printf("Secretbox failed\n");
        goto end;
    }
    memmove(dest, nonce, crypto_secretbox_NONCEBYTES);
    status =
        srcLength + crypto_secretbox_MACBYTES + crypto_secretbox_NONCEBYTES;

end:
    platform_secure_memset0(&bolosPersistentContext,
                            sizeof(bolos_persistent_context_t));
    mach->cpu.regs[MOXIE_R0] = status;
}

/*
* bls_unwrap
* $r0 -- scope bls_wrapping_scope_t
* $r1 -- in uint8_t*
* $r2 -- length size_t
* $r3 -- out uint8_t*
* $r4 -- outLength size_t
* Output:
* unsigned int
*/
void moxie_bls_unwrap(struct machine *mach) {
    uint32_t scope = mach->cpu.regs[MOXIE_R0];
    uint8_t *src;
    uint32_t srcLength = mach->cpu.regs[MOXIE_R2];
    uint8_t *dest;
    uint32_t destLength = mach->cpu.regs[MOXIE_R4];
    uint32_t status = 0;
    uint8_t *key;
    uint8_t tmpKey[crypto_secretbox_KEYBYTES];
    bolos_persistent_context_t bolosPersistentContext;

    if (destLength <
        srcLength - crypto_secretbox_MACBYTES - crypto_secretbox_NONCEBYTES) {
        printf("Output buffer length too small\n");
        goto end;
    }
    src = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R1], srcLength,
                                    false);
    if (src == NULL) {
        printf("Invalid input buffer\n");
        goto end;
    }
    dest = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R3], destLength,
                                     false);
    if (dest == NULL) {
        printf("Invalid output buffer\n");
        goto end;
    }

    switch (scope) {
    case BLS_SCOPE_DEVICE:
        if (!platform_read_persistent_context(&bolosPersistentContext)) {
            printf("Failed to read persistent context\n");
            goto end;
        }
        key = bolosPersistentContext.deviceWrappingKey;
        break;
    case BLS_SCOPE_APPLICATION: {
        if (!platform_read_persistent_context(&bolosPersistentContext)) {
            printf("Failed to read persistent context\n");
            goto end;
        }
        if (!platform_sha256_init() ||
            !platform_sha256_update(
                bolosPersistentContext.deviceWrappingKey,
                sizeof(bolosPersistentContext.deviceWrappingKey)) ||
            !platform_sha256_update(
                bolosTransientContext.runningExecCodeHash,
                sizeof(bolosTransientContext.runningExecCodeHash)) ||
            !platform_sha256_final(tmpKey)) {
            printf("Diversification failed\n");
            goto end;
        }
        key = tmpKey;
    } break;
    case BLS_SCOPE_SESSION:
        key = bolosTransientContext.sessionWrappingKey;
        break;
    case BLS_SCOPE_SESSION_APPLICATION: {
        if (!platform_sha256_init() ||
            !platform_sha256_update(
                bolosTransientContext.sessionWrappingKey,
                sizeof(bolosTransientContext.sessionWrappingKey)) ||
            !platform_sha256_update(
                bolosTransientContext.runningExecCodeHash,
                sizeof(bolosTransientContext.runningExecCodeHash)) ||
            !platform_sha256_final(tmpKey)) {
            printf("Diversification failed\n");
            goto end;
        }
        key = tmpKey;
    } break;
    case BLS_SCOPE_PERSONALIZATION:
        if (!bolosTransientContext.personalizationKeySet) {
            printf("Personalization key not set\n");
            goto end;
        }
        key = bolosTransientContext.personalizationKey;
        break;

    default:
        printf("Unsupported scope\n");
        goto end;
    }
    if (crypto_secretbox_open_easy(dest, src + crypto_secretbox_NONCEBYTES,
                                   srcLength - crypto_secretbox_NONCEBYTES, src,
                                   key)) {
        printf("Secretbox open failed\n");
        goto end;
    }
    status =
        srcLength - crypto_secretbox_MACBYTES - crypto_secretbox_NONCEBYTES;

end:
    platform_secure_memset0(&bolosPersistentContext,
                            sizeof(bolos_persistent_context_t));
    mach->cpu.regs[MOXIE_R0] = status;
}
