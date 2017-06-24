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
#include <stdint.h>
#include <string.h>
#include <assert.h>

#include "libsecp256k1-config.h"
#include "secp256k1.h"
#include "uECC.h"

#include "machine.h"
#include "moxie_swi_common.h"
#include "portable_msg.h"
#include "portable_persistent_context.h"
#include "portable_transient_context.h"
#include "platform_al.h"
#include "bolos.h"
#include "signal.h"

extern void sim_resume(struct machine *mach, unsigned long long cpu_budget);

#define MAX_MEMMAP_ENTRIES 10

secp256k1_context *secp256k1Context = NULL;
bolos_transient_context_t bolosTransientContext;
uint8_t *codeData = NULL;
uint32_t codeLength;
uint32_t codeCurrentOffset;

struct addressRange memoryMapping[MAX_MEMMAP_ENTRIES];
struct machine mach;

#if defined(SIMU)

// b1ed47ef58f782e2bc4d5abe70ef66d9009c2957967017054470e0f3e10f5833

static const uint8_t LEDGER_CODE_PUBLIC_KEY[] = {
    0x04,

    0x20, 0xda, 0x62, 0x00, 0x3c, 0x0c, 0xe0, 0x97, 0xe3, 0x36, 0x44,
    0xa1, 0x0f, 0xe4, 0xc3, 0x04, 0x54, 0x06, 0x9a, 0x44, 0x54, 0xf0,
    0xfa, 0x9d, 0x4e, 0x84, 0xf4, 0x50, 0x91, 0x42, 0x9b, 0x52,

    0x20, 0xaf, 0x9e, 0x35, 0xc0, 0xb2, 0xd9, 0x28, 0x93, 0x80, 0x13,
    0x73, 0x07, 0xde, 0x4d, 0xd1, 0xd4, 0x18, 0x42, 0x8c, 0xf2, 0x1a,
    0x93, 0xb3, 0x35, 0x61, 0xbb, 0x09, 0xd8, 0x8f, 0xe5, 0x79};

#else

static const uint8_t LEDGER_CODE_PUBLIC_KEY[] = {

    0x04,

    0xcc, 0xe1, 0x54, 0x19, 0xad, 0x94, 0xb2, 0xda, 0x64, 0x78, 0x24,
    0x49, 0x59, 0xa7, 0x1e, 0x7a, 0x8a, 0x0c, 0xe1, 0x2a, 0xf9, 0x8a,
    0x07, 0x65, 0x88, 0x30, 0xed, 0xf1, 0xbd, 0x4d, 0x1e, 0x2e,

    0x89, 0xda, 0xcb, 0x48, 0xb0, 0x4c, 0xad, 0xb8, 0x19, 0x07, 0x88,
    0xae, 0x0b, 0x1f, 0xe3, 0xad, 0x4c, 0x5f, 0xe8, 0xc9, 0xd6, 0x26,
    0x6f, 0x6e, 0x48, 0xcd, 0x63, 0x5f, 0xdc, 0xe7, 0x6a, 0x8c};

#endif

#ifdef SECP256K1_TEST
#include "tests_impl.h"
#else
#include "secp256k1.c"
#endif

#define CMD_TEST_SECP256K1 0xFFFF
#define CMD_TEST_RANDOM 0xFFFE

uint32_t read_u32_be(unsigned char *buffer) {
    return ((buffer[0] << 24) | (buffer[1] << 16) | (buffer[2] << 8) |
            buffer[3]);
}

int read_i32_be(unsigned char *buffer) {
    return ((buffer[0] << 24) | (buffer[1] << 16) | (buffer[2] << 8) |
            buffer[3]);
}

uint64_t read_u64_be(unsigned char *buffer) {
    return (((uint64_t)buffer[0] << 56) | ((uint64_t)buffer[1] << 48) |
            ((uint64_t)buffer[2] << 40) | ((uint64_t)buffer[3] << 32) |
            ((uint64_t)buffer[4] << 24) | ((uint64_t)buffer[5] << 16) |
            ((uint64_t)buffer[6] << 8) | (uint64_t)buffer[7]);
}

void write_u32_be(unsigned char *buffer, uint32_t value) {
    buffer[0] = (value >> 24);
    buffer[1] = (value >> 16);
    buffer[2] = (value >> 8);
    buffer[3] = (value & 0xff);
}

void write_u64_be(unsigned char *buffer, uint64_t value) {
    buffer[0] = (uint8_t)(value >> 56);
    buffer[1] = (uint8_t)(value >> 48);
    buffer[2] = (uint8_t)(value >> 40);
    buffer[3] = (uint8_t)(value >> 32);
    buffer[4] = (uint8_t)(value >> 24);
    buffer[5] = (uint8_t)(value >> 16);
    buffer[6] = (uint8_t)(value >> 8);
    buffer[7] = (value & 0xff);
}

int get_machine_hash(unsigned char *hash) {
    struct addressRange *current = (struct addressRange *)mach.memoryData;
    if (!platform_sha256_init()) {
        return 0;
    }
    while (current != NULL) {
        if (current->used) {
            if (!platform_sha256_update(current->buf, current->length)) {
                return 0;
            }
        }
        current = current->next;
    }
    if (!platform_sha256_update((uint8_t *)&mach.cpu, sizeof(mach.cpu))) {
        return 0;
    }
    if (!platform_sha256_final(hash)) {
        return 0;
    }

    return 1;
}

int get_free_execution_slot() {
    uint32_t i;
    for (i = 0; i < bolosTransientContext.numExecSlots; i++) {
        if (!bolosTransientContext.execSlots[i].busy) {
            bolosTransientContext.execSlots[i].busy = true;
            platform_assert(
                platform_random(bolosTransientContext.execSlots[i].slotKey,
                                crypto_secretbox_KEYBYTES));
            return i;
        }
    }
    return -1;
}

int dump_machine_state(uint32_t slotIndex, uint8_t *out, uint32_t length) {
    uint32_t rwSlots = 0;
    uint32_t offset = 0;
    uint32_t i;
    struct addressRange *current = (struct addressRange *)mach.memoryData;
    while (current != NULL) {
        if (current->used && !current->readOnly) {
            rwSlots++;
        }
        current = current->next;
    }
    // Start with the nonce
    if ((offset + crypto_secretbox_NONCEBYTES) > length) {
        return 0;
    }
    platform_random(out, crypto_secretbox_NONCEBYTES);
    offset += crypto_secretbox_NONCEBYTES;
    // Save the stack size
    if ((offset + 4) > length) {
        return 0;
    }
    write_u32_be(out + offset, bolosTransientContext.stackSize);
    offset += 4;
    // Dump all RW slots
    if ((offset + 4) > length) {
        return 0;
    }
    write_u32_be(out + offset, rwSlots);
    offset += 4;
    current = (struct addressRange *)mach.memoryData;
    while (current != NULL) {
        if (current->used && !current->readOnly) {
            if ((offset + 4 + 4 + current->length) > length) {
                return 0;
            }
            write_u32_be(out + offset, current->start);
            offset += 4;
            write_u32_be(out + offset, current->length);
            offset += 4;
            memmove(out + offset, current->buf, current->length);
            offset += current->length;
        }
        current = current->next;
    }
    // Dump machine state
    if ((offset + (4 * (NUM_MOXIE_REGS + 1)) + (4 * 256) + 4 + 4 + 8) >
        length) {
        return 0;
    }
    for (i = 0; i < (NUM_MOXIE_REGS + 1); i++) {
        write_u32_be(out + offset, mach.cpu.regs[i]);
        offset += 4;
    }
    for (i = 0; i < 256; i++) {
        write_u32_be(out + offset, mach.cpu.sregs[i]);
        offset += 4;
    }
    write_u32_be(out + offset, mach.cpu.cc);
    offset += 4;
    write_u32_be(out + offset, mach.cpu.exception);
    offset += 4;
    write_u64_be(out + offset, mach.cpu.insts);
    offset += 8;
    // Encrypt state
    if ((offset + crypto_secretbox_MACBYTES) > length) {
        return 0;
    }
    if (crypto_secretbox_easy(
            out + crypto_secretbox_NONCEBYTES,
            out + crypto_secretbox_NONCEBYTES,
            offset - crypto_secretbox_NONCEBYTES, out,
            bolosTransientContext.execSlots[slotIndex].slotKey)) {
        printf("State encryption failed\n");
        return 0;
    }
    // Save hash
    if (!get_machine_hash(
            bolosTransientContext.execSlots[slotIndex].stateHash)) {
        printf("Get machine hash failed\n");
        return 0;
    }
    return offset + crypto_secretbox_MACBYTES;
}

int restore_machine_state(uint32_t slotIndex, uint8_t *in, uint32_t length) {
    uint32_t rwSlots = 0;
    uint32_t offset = 0;
    uint32_t i;
    uint32_t stackSize;
    uint8_t hash[32];
    uint32_t hashLength;
    uint8_t error = 0;
    struct addressRange *current;
    bool hasStack = false;
    if (length < (crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES)) {
        return 0;
    }

    if (crypto_secretbox_open_easy(
            in + crypto_secretbox_NONCEBYTES, in + crypto_secretbox_NONCEBYTES,
            length - crypto_secretbox_NONCEBYTES, in,
            bolosTransientContext.execSlots[slotIndex].slotKey)) {
        printf("State decryption failed\n");
        return 0;
    }
    // Add the stack
    offset += crypto_secretbox_NONCEBYTES;
    if ((offset + 4) > length) {
        return 0;
    }
    stackSize = read_u32_be(in + offset);
    offset += 4;
    if ((codeCurrentOffset + stackSize) > codeLength) {
        printf("Invalid stack size\n");
        return 0;
    }
    /* Create a new stack segment if it doesn't already exist */
    current = (struct addressRange *)mach.memoryData;
    while (current != NULL) {
        if (current->used && (strcmp(current->name, "stack") == 0)) {
            hasStack = true;
            break;
        }
        current = current->next;
    }
    if (!hasStack &&
        !add_stack(&mach, codeData + codeCurrentOffset, stackSize)) {
        printf("Failed to add stack");
        return 0;
    }
    // Process RW slots
    if ((offset + 4) > length) {
        return 0;
    }
    rwSlots = read_u32_be(in + offset);
    offset += 4;
    for (i = 0; i < rwSlots; i++) {
        uint32_t start;
        uint32_t dataLength;
        if ((offset + 4 + 4) > length) {
            return 0;
        }
        start = read_u32_be(in + offset);
        offset += 4;
        dataLength = read_u32_be(in + offset);
        offset += 4;
        current = (struct addressRange *)mach.memoryData;
        while (current != NULL) {
            if (current->used && !current->readOnly &&
                (current->start == start) && (current->length == dataLength)) {
                break;
            }
            current = current->next;
        }
        if (current == NULL) {
            printf("Range not found\n");
            return 0;
        }
        if ((offset + dataLength) > length) {
            return 0;
        }
        memmove(current->buf, in + offset, dataLength);
        offset += dataLength;
    }
    // Restore machine state
    if ((offset + (4 * (NUM_MOXIE_REGS + 1)) + (4 * 256) + 4 + 4 + 8) >
        length) {
        return 0;
    }
    for (i = 0; i < (NUM_MOXIE_REGS + 1); i++) {
        mach.cpu.regs[i] = read_u32_be(in + offset);
        offset += 4;
    }
    for (i = 0; i < 256; i++) {
        mach.cpu.sregs[i] = read_u32_be(in + offset);
        offset += 4;
    }
    mach.cpu.cc = read_u32_be(in + offset);
    offset += 4;
    mach.cpu.exception = read_i32_be(in + offset);
    offset += 4;
    mach.cpu.insts = read_u64_be(in + offset);
    offset += 8;
    // Verify hash
    if (!get_machine_hash(hash)) {
        printf("Get machine hash failed\n");
        return 0;
    }
    hashLength = 32;
    while (hashLength--) {
        error |=
            hash[hashLength] ^
            bolosTransientContext.execSlots[slotIndex].stateHash[hashLength];
    }
    if (error) {
        printf("Machine hash differ\n");
        return 0;
    }
    return 1;
}

int uecc_rng(uint8_t *p_dest, unsigned p_size) {
    platform_assert(platform_random(p_dest, p_size));
    return 1;
}

bolos_exec_status_t bolos_handle_message(void *platformContext, uint8_t *buffer,
                                         uint32_t reqLength,
                                         uint32_t *outLength) {
    uint8_t *out = NULL, *inBuffer = (uint8_t *)buffer;
    uint16_t cmd;
    uint32_t offset = 0;
    uint32_t outLen_user;
    bolos_exec_status_t status = BOLOS_EXEC_INTERNAL;
    if (outLength == NULL) {
        return BOLOS_EXEC_INTERNAL;
    }
    if ((reqLength - offset) < 2) {
        return BOLOS_EXEC_INVALID_ARGUMENTS;
    }
    cmd = (inBuffer[offset] << 8) + (inBuffer[offset + 1]);
    offset += 2;
    out = platform_get_reply_buffer(platformContext, &outLen_user);
    if (out == NULL) {
        return BOLOS_EXEC_OUT_OF_MEMORY;
    }

    switch (cmd) {
#ifdef SECP256K1_TEST
    case CMD_TEST_SECP256K1:
        // Process
        printf("Test start ...\n");
        secp256k1Test();
        printf("Test end ...\n");
        out[0] = 0x01;
        *outLength = 1;
        status = BOLOS_EXEC_OK;
        break;
#endif

    case CMD_TEST_RANDOM: {
        uint32_t randomLength;
        if ((reqLength - offset) < 2) {
            status = BOLOS_EXEC_INVALID_ARGUMENTS;
            break;
        }
        randomLength = (inBuffer[offset] << 8) + (inBuffer[offset + 1]);
        offset += 2;
        if (randomLength > outLen_user) {
            status = BOLOS_EXEC_INVALID_ARGUMENTS;
            break;
        }
        platform_assert(platform_random(out, randomLength));
        *outLength = randomLength;
        status = BOLOS_EXEC_OK;
    } break;

    case CMD_SESSION_OPEN: {
        if ((bolosTransientContext.sessionOpened) &&
            (bolosTransientContext.parameters != NULL)) {
            free(bolosTransientContext.parameters);
            bolosTransientContext.parameters = NULL;
        }
        platform_secure_memset0(&bolosTransientContext,
                                sizeof(bolosTransientContext));
        moxie_swi_shared_memory_init();
        platform_assert(
            platform_random(bolosTransientContext.sessionWrappingKey,
                            sizeof(bolosTransientContext.sessionWrappingKey)));
        if ((reqLength - offset) >= 8) {
            uint32_t i;
            bolosTransientContext.numExecSlots = read_u32_be(inBuffer + offset);
            offset += 4;
            bolosTransientContext.timeoutExecSlot =
                read_u32_be(inBuffer + offset);
            offset += 4;
            bolosTransientContext.execSlots = (bolos_exec_slot_t *)malloc(
                bolosTransientContext.numExecSlots * sizeof(bolos_exec_slot_t));
            if (bolosTransientContext.execSlots == NULL) {
                status = BOLOS_EXEC_INVALID_ARGUMENTS;
                break;
            }
            for (i = 0; i < bolosTransientContext.numExecSlots; i++) {
                bolosTransientContext.execSlots[i].busy = false;
            }
        }
        out[0] = STATUS_CODE_EXEC_OK;
        if (outLen_user >= 1) {
            *outLength = 1;
            bolosTransientContext.sessionOpened = true;
            status = BOLOS_EXEC_OK;
        } else {
            status = BOLOS_EXEC_INVALID_ARGUMENTS;
        }
    } break;

    case CMD_SESSION_CLOSE: {
        if (bolosTransientContext.sessionOpened) {
            if (bolosTransientContext.parameters != NULL) {
                free(bolosTransientContext.parameters);
                bolosTransientContext.parameters = NULL;
            }
            if (bolosTransientContext.execSlots != NULL) {
                free(bolosTransientContext.execSlots);
                bolosTransientContext.execSlots = NULL;
                bolosTransientContext.numExecSlots = 0;
            }
        }
        platform_secure_memset0(&bolosTransientContext,
                                sizeof(bolosTransientContext));
        moxie_swi_shared_memory_cleanup();
        out[0] = STATUS_CODE_EXEC_OK;
        if (outLen_user >= 1) {
            *outLength = 1;
            status = BOLOS_EXEC_OK;
        } else {
            status = BOLOS_EXEC_INVALID_ARGUMENTS;
        }
    } break;

    case CMD_CODE_INIT: {
        coderuntime_init_query_t initQuery;
        uint32_t i;
        if ((outLen_user < 1) || ((reqLength - offset) < 4)) {
            status = BOLOS_EXEC_INVALID_ARGUMENTS;
            break;
        }
        // Cleanup
        if (codeData != NULL) {
            free(codeData);
            codeData = NULL;
        }
        if (!platform_sha256_init()) {
            printf("Hash init failed\n");
            status = BOLOS_EXEC_INTERNAL;
            break;
        }
        if ((bolosTransientContext.sessionOpened) &&
            (bolosTransientContext.parameters != NULL)) {
            free(bolosTransientContext.parameters);
            bolosTransientContext.parameters = NULL;
        }
        // Deny if the session was not opened
        if (!bolosTransientContext.sessionOpened) {
            printf("CODE_INIT: Session not opened\n");
            out[0] = STATUS_CODE_EXEC_ERROR;
            goto replyInit;
        }
        // Read arguments
        initQuery.loadSize = read_u32_be(inBuffer + offset);
        platform_secure_memset0(&memoryMapping, sizeof(memoryMapping));
        for (i = 0; i < MAX_MEMMAP_ENTRIES; i++) {
            if (i != (MAX_MEMMAP_ENTRIES - 1)) {
                memoryMapping[i].next = &memoryMapping[i + 1];
            }
        }
        if (!machine_init(&mach, memoryMapping)) {
            printf("Moxie initialization failed\n");
            status = BOLOS_EXEC_OUT_OF_MEMORY;
            break;
        }
        codeLength = initQuery.loadSize;
        codeCurrentOffset = 0;
        codeData = (uint8_t *)malloc(codeLength);
        if (codeData == NULL) {
            printf("Failed to allocate code memory for %d\n", codeLength);
            status = BOLOS_EXEC_OUT_OF_MEMORY;
            break;
        }
        platform_secure_memset0(codeData, codeLength);
        out[0] = STATUS_CODE_EXEC_OK;
    replyInit:
        status = BOLOS_EXEC_OK;
        *outLength = 1;
    } break;

    case CMD_CODE_LOAD_SECTION: {
        coderuntime_load_section_query_t loadQuery;
        struct addressRange range = {0};
        if ((outLen_user < 1) || ((reqLength - offset) < (1 + 4 + 4 + 4))) {
            status = BOLOS_EXEC_INVALID_ARGUMENTS;
            break;
        }
        // Deny if the session was not opened
        if (!bolosTransientContext.sessionOpened || (codeData == NULL)) {
            printf("CODE_LOAD: Session not opened\n");
            out[0] = STATUS_CODE_EXEC_ERROR;
            goto replyLoad;
        }
        // Add to hash
        if (!platform_sha256_update(inBuffer + offset, 1 + 4 + 4 + 4)) {
            printf("Hash update failed\n");
            status = BOLOS_EXEC_INTERNAL;
            break;
        }
        // Read arguments
        loadQuery.flags = inBuffer[offset++];
        loadQuery.sectionStart = read_u32_be(inBuffer + offset);
        offset += 4;
        loadQuery.sectionEnd = read_u32_be(inBuffer + offset);
        offset += 4;
        loadQuery.sectionDataLength = read_u32_be(inBuffer + offset);
        offset += 4;
        if ((codeCurrentOffset +
             (loadQuery.sectionEnd - loadQuery.sectionStart)) > codeLength) {
            printf("Code mapping overflow\n");
            out[0] = STATUS_CODE_EXEC_ERROR;
            goto replyLoad;
        }
        if ((reqLength - offset) < loadQuery.sectionDataLength) {
            status = BOLOS_EXEC_INVALID_ARGUMENTS;
            break;
        }
        platform_secure_memset0(
            codeData + codeCurrentOffset,
            (loadQuery.sectionEnd - loadQuery.sectionStart));
        memmove(codeData + codeCurrentOffset, inBuffer + offset,
                loadQuery.sectionDataLength);
        // Add to hash
        if (!platform_sha256_update(codeData + codeCurrentOffset,
                                    loadQuery.sectionDataLength)) {
            printf("Hash update failed\n");
            status = BOLOS_EXEC_INTERNAL;
            break;
        }
        range.start = loadQuery.sectionStart;
        range.end = loadQuery.sectionEnd;
        range.length = (loadQuery.sectionEnd - loadQuery.sectionStart);
        range.readOnly =
            ((loadQuery.flags & MSG_LOAD_SECTION_FLAG_READ_ONLY) != 0);
        range.buf = (codeData + codeCurrentOffset);
        codeCurrentOffset += range.length;
        if (!add_addressRange(&mach, &range)) {
            printf("Failed to add range\n");
            out[0] = STATUS_CODE_EXEC_ERROR;
            goto replyLoad;
        }
        out[0] = STATUS_CODE_EXEC_OK;
    replyLoad:
        *outLength = 1;
        status = BOLOS_EXEC_OK;
    } break;

    case CMD_CODE_RUN: {
        uint32_t returnLength = 0;
        coderuntime_run_code_query_t runQuery;
        secp256k1_ecdsa_signature sigInternal;
        secp256k1_pubkey pubkey;
        int ret;
        bool hashResult;
        if ((outLen_user < 1) || ((reqLength - offset) < (4 + 4 + 4 + 4 + 4))) {
            status = BOLOS_EXEC_INVALID_ARGUMENTS;
            break;
        }
        // Deny if the session was not opened
        if (!bolosTransientContext.sessionOpened || (codeData == NULL)) {
            printf("CODE_RUN:Session not opened\n");
            out[0] = STATUS_CODE_EXEC_ERROR;
            returnLength = 1;
            goto replyRun;
        }
        // Add to hash
        hashResult = platform_sha256_update(inBuffer + offset, 4);
        if (hashResult) {
            hashResult = platform_sha256_final(
                bolosTransientContext.runningExecCodeHash);
        }
        if (!hashResult) {
            printf("Hash finish failed\n");
            status = BOLOS_EXEC_INTERNAL;
            break;
        }
        runQuery.entryPoint = read_u32_be(inBuffer + offset);
        offset += 4;
        runQuery.stackSize = read_u32_be(inBuffer + offset);
        offset += 4;
        runQuery.uiDataLength = read_u32_be(inBuffer + offset);
        offset += 4;
        runQuery.inputDataLength = read_u32_be(inBuffer + offset);
        offset += 4;
        runQuery.signatureLength = read_u32_be(inBuffer + offset);
        offset += 4;
        if ((reqLength - offset) <
            (runQuery.uiDataLength + runQuery.inputDataLength +
             runQuery.signatureLength)) {
            status = BOLOS_EXEC_INVALID_ARGUMENTS;
            break;
        }
        if ((codeCurrentOffset + runQuery.stackSize) > codeLength) {
            printf("Stack mapping overflow %d %d %d\n", codeCurrentOffset,
                   runQuery.stackSize, codeLength);
            out[0] = STATUS_CODE_EXEC_ERROR;
            returnLength = 1;
            goto replyRun;
        }
        if (!add_stack(&mach, codeData + codeCurrentOffset,
                       runQuery.stackSize)) {
            printf("Failed to add stack");
            out[0] = STATUS_CODE_EXEC_ERROR;
            returnLength = 1;
            goto replyRun;
        }
        // Verify signature
        if (!secp256k1_ecdsa_signature_parse_der(secp256k1Context, &sigInternal,
                                                 inBuffer + offset +
                                                     runQuery.uiDataLength +
                                                     runQuery.inputDataLength,
                                                 runQuery.signatureLength)) {
            printf("Unserialize DER failed\n");
            status = BOLOS_EXEC_INVALID_ARGUMENTS;
            break;
        }
        ret = secp256k1_ec_pubkey_parse(
            secp256k1Context, &pubkey,
            (!bolosTransientContext.tokenPublicKeyUsed
                 ? LEDGER_CODE_PUBLIC_KEY
                 : bolosTransientContext.tokenPublicKey),
            65);
        if (ret != 1) {
            printf("Key parsing failed %d\n", ret);
            out[0] = STATUS_CODE_EXEC_ERROR;
            returnLength = 1;
            goto replyRun;
        }
        ret = secp256k1_ecdsa_verify(secp256k1Context, &sigInternal,
                                     bolosTransientContext.runningExecCodeHash,
                                     &pubkey);
        if (ret != 1) {
            printf("Signature verify failed %d\n", ret);
            out[0] = STATUS_CODE_EXEC_ERROR;
            returnLength = 1;
            goto replyRun;
        }
        mach.startAddr = runQuery.entryPoint;
        mach.cpu.regs[PC_REGNO] = mach.startAddr;
        bolosTransientContext.outLength = 0;
        bolosTransientContext.outBuffer = out;
        bolosTransientContext.outLengthMax = outLen_user;
        bolosTransientContext.stackSize = runQuery.stackSize;
        if (bolosTransientContext.parameters != NULL) {
            free(bolosTransientContext.parameters);
        }
        if (runQuery.inputDataLength != 0) {
            bolosTransientContext.parameters =
                (uint8_t *)malloc(runQuery.inputDataLength);
            if (bolosTransientContext.parameters == NULL) {
                printf("Failed to allocate parameters\n");
                status = BOLOS_EXEC_OUT_OF_MEMORY;
                break;
            }
            memmove(bolosTransientContext.parameters,
                    inBuffer + offset + runQuery.uiDataLength,
                    runQuery.inputDataLength);
        } else {
            bolosTransientContext.parameters = NULL;
        }
        bolosTransientContext.parametersLength = runQuery.inputDataLength;
        moxie_swi_crypto_init();
        sim_resume(&mach, 0);
        moxie_swi_crypto_cleanup();
        platform_secure_memset0(codeData, codeLength);
        free(codeData);
        codeData = NULL;
        if ((mach.cpu.exception != SIGQUIT) &&
            (mach.cpu.exception != SIGSUSPEND)) {
            printf("Execution error %d\n", mach.cpu.exception);
            out[0] = STATUS_CODE_EXEC_ERROR + mach.cpu.exception;
            returnLength = 1;
        } else {
            returnLength = bolosTransientContext.outLength;
        }
    replyRun:
        *outLength = returnLength;
        status = BOLOS_EXEC_OK;
        break;
    }

    case CMD_CODE_RESUME: {
        uint32_t returnLength = 0;
        coderuntime_resume_code_query_t resumeQuery;
        if ((outLen_user < 1) || ((reqLength - offset) < (4 + 4 + 4 + 4))) {
            status = BOLOS_EXEC_INVALID_ARGUMENTS;
            break;
        }
        // Deny if the session was not opened
        if (!bolosTransientContext.sessionOpened || (codeData == NULL)) {
            printf("CODE_RESUME: Session not opened\n");
            out[0] = STATUS_CODE_EXEC_ERROR;
            returnLength = 1;
            goto replyResume;
        }
        resumeQuery.slot = read_u32_be(inBuffer + offset);
        offset += 4;
        resumeQuery.stateBlobSize = read_u32_be(inBuffer + offset);
        offset += 4;
        resumeQuery.uiDataLength = read_u32_be(inBuffer + offset);
        offset += 4;
        resumeQuery.inputDataLength = read_u32_be(inBuffer + offset);
        offset += 4;
        if (resumeQuery.slot == 0) {
            printf("Null slot not supported\n");
            out[0] = STATUS_CODE_EXEC_ERROR;
            returnLength = 1;
            goto replyResume;
        }
        resumeQuery.slot--;
        if ((resumeQuery.slot >= bolosTransientContext.numExecSlots) ||
            !bolosTransientContext.execSlots[resumeQuery.slot].busy) {
            printf("Invalid resume slot\n");
            out[0] = STATUS_CODE_EXEC_ERROR;
            returnLength = 1;
            goto replyResume;
        }
        // Attempt recovery
        if (!restore_machine_state(resumeQuery.slot, inBuffer + offset,
                                   resumeQuery.stateBlobSize)) {
            bolosTransientContext.execSlots[resumeQuery.slot].busy = false;
            printf("Failed to resume state\n");
            out[0] = STATUS_CODE_EXEC_ERROR;
            returnLength = 1;
            goto replyResume;
        }
        bolosTransientContext.execSlots[resumeQuery.slot].busy = false;
        // Include the new input parameters
        bolosTransientContext.outLength = 0;
        bolosTransientContext.outBuffer = out;
        bolosTransientContext.outLengthMax = outLen_user;
        if (bolosTransientContext.parameters != NULL) {
            free(bolosTransientContext.parameters);
        }
        if (resumeQuery.inputDataLength != 0) {
            bolosTransientContext.parameters =
                (uint8_t *)malloc(resumeQuery.inputDataLength);
            if (bolosTransientContext.parameters == NULL) {
                printf("Failed to allocate parameters\n");
                status = BOLOS_EXEC_OUT_OF_MEMORY;
                break;
            }
            memmove(bolosTransientContext.parameters,
                    inBuffer + offset + resumeQuery.stateBlobSize +
                        resumeQuery.uiDataLength,
                    resumeQuery.inputDataLength);
        } else {
            bolosTransientContext.parameters = NULL;
        }
        bolosTransientContext.parametersLength = resumeQuery.inputDataLength;
        // Skip the last SWI call that initiated the suspend and resume
        mach.cpu.regs[PC_REGNO] += 6;
        moxie_swi_crypto_init();
        sim_resume(&mach, 0);
        moxie_swi_crypto_cleanup();
        if ((mach.cpu.exception != SIGQUIT) &&
            (mach.cpu.exception != SIGSUSPEND)) {
            printf("Execution error %d\n", mach.cpu.exception);
            out[0] = STATUS_CODE_EXEC_ERROR + mach.cpu.exception;
            returnLength = 1;
        } else {
            returnLength = bolosTransientContext.outLength;
        }

    replyResume:
        *outLength = returnLength;
        status = BOLOS_EXEC_OK;
        break;
    }

    case CMD_GET_PLATFORM_ID: {
        uint32_t idLength;
        idLength = platform_get_id(out + 1, outLen_user);
        if (idLength == 0) {
            status = BOLOS_EXEC_INVALID_ARGUMENTS;
            break;
        }
        out[0] = STATUS_CODE_EXEC_OK;
        *outLength = idLength + 1;
        status = BOLOS_EXEC_OK;
        break;
    }

    case CMD_PROVIDE_TOKEN: {
        uint8_t publicKey[65];
        uint8_t hash[32];
        uint32_t idLength;
        uint32_t signatureLength;
        secp256k1_ecdsa_signature sigInternal;
        secp256k1_pubkey pubkey;
        int ret;
        if ((outLen_user < 1) || ((reqLength - offset) < (65 + 4 + 4))) {
            status = BOLOS_EXEC_INVALID_ARGUMENTS;
            break;
        }
        // Deny if the session was not opened
        if (!bolosTransientContext.sessionOpened) {
            out[0] = STATUS_CODE_EXEC_ERROR;
            *outLength = 1;
            status = BOLOS_EXEC_OK;
            break;
        }
        memmove(publicKey, inBuffer + offset, 65);
        offset += 65;
        idLength = read_u32_be(inBuffer + offset);
        offset += 4;
        signatureLength = read_u32_be(inBuffer + offset);
        offset += 4;
        // Verify the ID and signature
        if (!platform_verify_id(inBuffer + offset, idLength)) {
            printf("Invalid platform ID\n");
            status = BOLOS_EXEC_INVALID_ARGUMENTS;
            break;
        }
        if (!platform_sha256_init()) {
            printf("Hash init failed\n");
            status = BOLOS_EXEC_INTERNAL;
            break;
        }
        if (!platform_sha256_update(publicKey, 65)) {
            printf("Hash update failed\n");
            status = BOLOS_EXEC_INTERNAL;
            break;
        }
        if (!platform_sha256_update(inBuffer + offset, idLength)) {
            printf("Hash update failed\n");
            status = BOLOS_EXEC_INTERNAL;
            break;
        }
        if (!platform_sha256_final(hash)) {
            printf("Hash final failed\n");
            status = BOLOS_EXEC_INTERNAL;
            break;
        }
        // Verify signature
        if (!secp256k1_ecdsa_signature_parse_der(secp256k1Context, &sigInternal,
                                                 inBuffer + offset + idLength,
                                                 signatureLength)) {
            printf("Unserialize DER failed\n");
            status = BOLOS_EXEC_INVALID_ARGUMENTS;
            break;
        }
        ret = secp256k1_ec_pubkey_parse(secp256k1Context, &pubkey,
                                        LEDGER_CODE_PUBLIC_KEY, 65);
        if (ret) {
            ret = secp256k1_ecdsa_verify(secp256k1Context, &sigInternal, hash,
                                         &pubkey);
        }
        if (ret != 1) {
            printf("Signature verify failed %d\n", ret);
            status = BOLOS_EXEC_INVALID_ARGUMENTS;
            break;
        }
        // Commit the key for this session
        memmove(bolosTransientContext.tokenPublicKey, publicKey, 65);
        bolosTransientContext.tokenPublicKeyUsed = true;
        out[0] = STATUS_CODE_EXEC_OK;
        *outLength = 1;
        status = BOLOS_EXEC_OK;
        break;
    }

    case CMD_GET_VERSION: {
        uint32_t versionLength;
        versionLength = platform_get_version_string(out + 1, outLen_user);
        if (versionLength == 0) {
            status = BOLOS_EXEC_INVALID_ARGUMENTS;
            break;
        }
        out[0] = STATUS_CODE_EXEC_OK;
        *outLength = versionLength + 1;
        status = BOLOS_EXEC_OK;

        break;
    }

    default:
        status = BOLOS_EXEC_UNSUPPORTED;
        break;
    }

    return status;
}

bool bolos_init() {
    secp256k1Context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                SECP256K1_CONTEXT_VERIFY);
    if (secp256k1Context == NULL) {
        printf("secp256k1context initialization failed\n");
        return false;
    }
    uECC_set_rng(uecc_rng);
    platform_secure_memset0(&bolosTransientContext,
                            sizeof(bolosTransientContext));
    return true;
}

bool bolos_uninit() {
    if (secp256k1Context != NULL) {
        secp256k1_context_destroy(secp256k1Context);
        secp256k1Context = NULL;
    }
    return true;
}
