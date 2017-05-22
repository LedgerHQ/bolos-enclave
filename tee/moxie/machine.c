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

#include "machine.h"

#ifndef SGX
#include <stdio.h>
#include <stdlib.h>
#define TRACE printf
#else
#define TRACE
#endif

bool isInRange(struct addressRange *range, uint32_t addr, uint32_t length) {
    return ((addr >= range->start) && ((addr + length) <= range->end));
}

bool isCrossing(struct addressRange *range1, struct addressRange *range2) {
    if ((range2->start >= range1->start) && (range2->start < range1->end)) {
        return true;
    }
    if ((range2->end >= range1->start) && (range2->end <= range1->end)) {
        return true;
    }
    return false;
}

bool machine_init(struct machine *mach, struct addressRange *memoryData) {
    memset(mach, 0, sizeof(struct machine));
    mach->memoryData = (void *)memoryData;
    return true;
}

bool add_addressRange(struct machine *mach, struct addressRange *newSection) {
    struct addressRange *memory = (struct addressRange *)mach->memoryData;
    struct addressRange *current = memory;
    // Look for collisions
    while (current != NULL) {
        if (current->used) {
            if (isCrossing(current, newSection)) {
                return false;
            }
        }
        current = current->next;
    }
    // Look for a free space
    current = memory;
    while (current != NULL) {
        if (!current->used) {
            break;
        }
        current = current->next;
    }
    if (current == NULL) {
        return false;
    }
    // Fill up
    memmove(current->name, newSection->name, MAX_NAME);
    current->start = newSection->start;
    current->end = newSection->end;
    current->length = newSection->length;
    current->readOnly = newSection->readOnly;
    current->used = true;
    current->buf = newSection->buf;
    return true;
}

bool add_newSection(struct machine *mach, struct addressRange *newSection) {
    struct addressRange *current = (struct addressRange *)mach->memoryData;
    struct addressRange *freeSection = NULL;
    uint32_t endAddress = 0;
    while (current != NULL) {
        if (!current->used && (freeSection == NULL)) {
            freeSection = current;
        }
        if (current->used) {
            if (current->end > endAddress) {
                endAddress = current->end;
            }
        }
        current = current->next;
    }
    if (freeSection == NULL) {
        return false;
    }
    // Fill up
    memmove(freeSection->name, newSection->name, MAX_NAME);
    freeSection->start = endAddress + MACH_PAGE_SIZE;
    freeSection->end = freeSection->start + newSection->length;
    freeSection->length = newSection->length;
    freeSection->readOnly = newSection->readOnly;
    freeSection->used = true;
    freeSection->buf = newSection->buf;
    // Return address
    newSection->start = freeSection->start;
    newSection->end = freeSection->end;
    return true;
}

bool add_stack(struct machine *mach, uint8_t *stackBuffer, uint32_t length) {
    struct addressRange newSection = {0};
    memmove(newSection.name, "stack", 6);
    newSection.length = length;
    newSection.buf = stackBuffer;
    if (!add_newSection(mach, &newSection)) {
        return false;
    }
    mach->cpu.sregs[SREG_CRT_STACK] = newSection.end;
    // printf("End of stack %.8x\n", newSection.end);
    return true;
}

uint8_t *physaddr(struct machine *mach, uint32_t addr, size_t objLen,
                  bool wantWrite) {
    struct addressRange *current = (struct addressRange *)mach->memoryData;
    while (current) {
        if (isInRange(current, addr, objLen)) {
            if (wantWrite && current->readOnly) {
                return NULL;
            }
            return (uint8_t *)((uint8_t *)current->buf +
                               (addr - current->start));
        }
        current = current->next;
    }
    return NULL;
}

bool read8(struct machine *mach, uint32_t addr, uint32_t *val_out) {
    uint8_t *paddr = physaddr(mach, addr, 1, false);
    if (!paddr) {
        TRACE("EXCEPTION read8 %x\n", addr);
        return false;
    }
    *val_out = *paddr;
    return true;
}

bool read16(struct machine *mach, uint32_t addr, uint32_t *val_out) {
    uint8_t *paddr = physaddr(mach, addr, 2, false);
    if (!paddr) {
        TRACE("EXCEPTION read16 %x\n", addr);
        return false;
    }
    *val_out = (*(paddr + 1) << 8) | *(paddr);
    return true;
}

bool read32(struct machine *mach, uint32_t addr, uint32_t *val_out) {
    uint8_t *paddr = physaddr(mach, addr, 4, false);
    if (!paddr) {
        TRACE("EXCEPTION read32 %x\n", addr);
        return false;
    }
    *val_out = (*(paddr + 3) << 24) | (*(paddr + 2) << 16) |
               (*(paddr + 1) << 8) | (*(paddr));
    return true;
}

bool read64(struct machine *mach, uint32_t addr, uint64_t *val_out) {
    uint8_t *paddr = physaddr(mach, addr, 8, false);
    if (!paddr) {
        TRACE("EXCEPTION read64 %x\n", addr);
        return false;
    }
    *val_out =
        ((uint64_t)(*(paddr + 7)) << 56) | ((uint64_t)(*(paddr + 6)) << 48) |
        ((uint64_t)(*(paddr + 5)) << 40) | ((uint64_t)(*(paddr + 4)) << 32) |
        ((uint64_t)(*(paddr + 3)) << 24) | ((uint64_t)(*(paddr + 2)) << 16) |
        ((uint64_t)(*(paddr + 1)) << 8) | (uint64_t)(*(paddr));
    return true;
}

bool write8(struct machine *mach, uint32_t addr, uint32_t val) {
    uint8_t *paddr = physaddr(mach, addr, 1, true);
    if (!paddr) {
        TRACE("EXCEPTION write8 %x\n", addr);
        return false;
    }
    *paddr = (uint8_t)val;
    return true;
}

bool write16(struct machine *mach, uint32_t addr, uint32_t val) {
    uint8_t *paddr = physaddr(mach, addr, 2, true);
    if (!paddr) {
        TRACE("EXCEPTION write16 %x\n", addr);
        return false;
    }
    *(paddr + 1) = (uint8_t)((val >> 8) & 0xff);
    *(paddr) = (uint8_t)(val & 0xff);
    return true;
}

bool write32(struct machine *mach, uint32_t addr, uint32_t val) {
    uint8_t *paddr = physaddr(mach, addr, 4, true);
    if (!paddr) {
        TRACE("EXCEPTION write32 %x\n", addr);
        return false;
    }
    *(paddr + 3) = (uint8_t)((val >> 24) & 0xff);
    *(paddr + 2) = (uint8_t)((val >> 16) & 0xff);
    *(paddr + 1) = (uint8_t)((val >> 8) & 0xff);
    *(paddr) = (uint8_t)(val & 0xff);
    return true;
}

bool write64(struct machine *mach, uint32_t addr, uint64_t val) {
    uint8_t *paddr = physaddr(mach, addr, 8, true);
    if (!paddr) {
        TRACE("EXCEPTION write64 %x\n", addr);
        return false;
    }
    *(paddr + 7) = (uint8_t)((val >> 56) & 0xff);
    *(paddr + 6) = (uint8_t)((val >> 48) & 0xff);
    *(paddr + 5) = (uint8_t)((val >> 40) & 0xff);
    *(paddr + 4) = (uint8_t)((val >> 32) & 0xff);
    *(paddr + 3) = (uint8_t)((val >> 24) & 0xff);
    *(paddr + 2) = (uint8_t)((val >> 16) & 0xff);
    *(paddr + 1) = (uint8_t)((val >> 8) & 0xff);
    *(paddr) = (uint8_t)(val & 0xff);
    return true;
}
