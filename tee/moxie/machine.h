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

/* Simulator for the moxie processor
   Copyright 2014 Anthony Green
   Distributed under the MIT/X11 software license, see the accompanying
   file COPYING or http://www.opensource.org/licenses/mit-license.php.
*/

#ifndef __MACHINE_H__
#define __MACHINE_H__

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "moxie.h"

#define MAX_NAME 10

struct mach_memmap_ent {
    uint32_t vaddr;
    uint32_t length;
    char tags[32 - 4 - 4];
};

struct addressRange {
    char name[MAX_NAME];
    uint32_t start;
    uint32_t end;
    uint32_t length;
    bool readOnly;
    bool used;
    void *buf;
    struct addressRange *next;
};

enum {
    MACH_PAGE_SIZE = 4096,
    MACH_PAGE_MASK = (MACH_PAGE_SIZE - 1),
};

#define SREG_CRT_STACK 7

struct machine {
    struct moxie_regset cpu;
    uint32_t startAddr;
    bool tracing;
    void *memoryData;
};

extern bool read8(struct machine *mach, uint32_t addr, uint32_t *val_out);
extern bool read16(struct machine *mach, uint32_t addr, uint32_t *val_out);
extern bool read32(struct machine *mach, uint32_t addr, uint32_t *val_out);
extern bool read64(struct machine *mach, uint32_t addr, uint64_t *val_out);
extern bool write8(struct machine *mach, uint32_t addr, uint32_t val);
extern bool write16(struct machine *mach, uint32_t addr, uint32_t val);
extern bool write32(struct machine *mach, uint32_t addr, uint32_t val);
extern bool write64(struct machine *mach, uint32_t addr, uint64_t val);

bool machine_init(struct machine *mach, struct addressRange *memoryData);
bool add_addressRange(struct machine *mach, struct addressRange *newSection);
bool add_newSection(struct machine *mach, struct addressRange *newSection);
bool add_stack(struct machine *mach, uint8_t *stackBuffer, uint32_t length);
uint8_t *physaddr(struct machine *mach, uint32_t addr, size_t objLen,
                  bool wantWrite);

#endif // __MACHINE_H__
