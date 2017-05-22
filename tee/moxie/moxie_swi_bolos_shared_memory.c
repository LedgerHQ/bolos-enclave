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

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include "signal.h"
#include <errno.h>
#include "bolos.h"
#include "machine.h"
#include "moxie_swi_common.h"
#include "platform_al.h"

uint8_t *bolos_shared_memory = NULL;

void moxie_swi_shared_memory_init(void) {
    bolos_shared_memory = (uint8_t *)malloc(BOLOS_SHARED_MEMORY_SIZE);
    if (bolos_shared_memory == NULL) {
        printf("Failed to allocate shared memory\n");
    } else {
        platform_secure_memset0(bolos_shared_memory, BOLOS_SHARED_MEMORY_SIZE);
    }
}

void moxie_swi_shared_memory_cleanup(void) {
    if (bolos_shared_memory != NULL) {
        platform_secure_memset0(bolos_shared_memory, BOLOS_SHARED_MEMORY_SIZE);
        free(bolos_shared_memory);
    }
}

/*
* bls_sharedmemory_get_size
* Output:
* int
*/
void moxie_bls_sharedmemory_get_size(struct machine *mach) {
    mach->cpu.regs[MOXIE_R0] =
        (bolos_shared_memory == NULL ? 0 : BOLOS_SHARED_MEMORY_SIZE);
}

/*
* bls_sharedmemory_read
* $r0 -- parameters uint8_t*
* $r1 -- offset uint32_t
* $r2 -- parametersLength size_t
* Output:
* size_t
*/
void moxie_bls_sharedmemory_read(struct machine *mach) {
    uint32_t offset = mach->cpu.regs[MOXIE_R1];
    uint32_t length = mach->cpu.regs[MOXIE_R2];
    uint32_t memorySize =
        (bolos_shared_memory == NULL ? 0 : BOLOS_SHARED_MEMORY_SIZE);
    if ((offset + length) > memorySize) {
        printf("Shared Memory read copy overflow\n");
        mach->cpu.exception = SIGBUS;
    } else {
        uint8_t *buffer = (uint8_t *)physaddr_check(
            mach, mach->cpu.regs[MOXIE_R0], length, true);
        if (buffer) {
            memmove(buffer, bolos_shared_memory + offset, length);
            mach->cpu.regs[MOXIE_R0] = length;
        } else {
            printf("Shared Memory destination buffer overflow\n");
            mach->cpu.exception = SIGBUS;
        }
    }
}

/*
* bls_sharedmemory_write
* $r0 -- parameters uint8_t*
* $r1 -- offset uint32_t
* $r2 -- parametersLength size_t
* Output:
* size_t
*/
void moxie_bls_sharedmemory_write(struct machine *mach) {
    uint32_t offset = mach->cpu.regs[MOXIE_R1];
    uint32_t length = mach->cpu.regs[MOXIE_R2];
    uint32_t memorySize =
        (bolos_shared_memory == NULL ? 0 : BOLOS_SHARED_MEMORY_SIZE);
    if ((offset + length) > memorySize) {
        printf("Shared Memory read write overflow\n");
        mach->cpu.exception = SIGBUS;
    } else {
        uint8_t *buffer = (uint8_t *)physaddr_check(
            mach, mach->cpu.regs[MOXIE_R0], length, false);
        if (buffer) {
            memmove(bolos_shared_memory + offset, buffer, length);
            mach->cpu.regs[MOXIE_R0] = length;
        } else {
            printf("Shared Memory source buffer overflow\n");
            mach->cpu.exception = SIGBUS;
        }
    }
}
