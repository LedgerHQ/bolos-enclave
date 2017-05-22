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

#include "bolos.h"
#include "moxie_swi_common.h"

uint8_t *physaddr_check(struct machine *mach, uint32_t addr, size_t objLen,
                        bool wantWrite) {
    uint8_t *result = physaddr(mach, addr, objLen, wantWrite);
    if (result == NULL) {
        mach->cpu.exception = SIGBUS;
    }
    return result;
}

bool read8_check(struct machine *mach, uint32_t addr, uint8_t *val_out) {
    uint32_t tmp;
    bool result = read8(mach, addr, &tmp);
    if (!result) {
        mach->cpu.exception = SIGBUS;
    }
    *val_out = tmp;
    return result;
}

bool write8_check(struct machine *mach, uint32_t addr, uint8_t val) {
    bool result = write8(mach, addr, val);
    if (!result) {
        mach->cpu.exception = SIGBUS;
    }
    return result;
}

bool read32_check(struct machine *mach, uint32_t addr, uint32_t *val_out) {
    bool result = read32(mach, addr, val_out);
    if (!result) {
        mach->cpu.exception = SIGBUS;
    }
    return result;
}

bool write32_check(struct machine *mach, uint32_t addr, uint32_t val) {
    bool result = write32(mach, addr, val);
    if (!result) {
        mach->cpu.exception = SIGBUS;
    }
    return result;
}

bool read64_check(struct machine *mach, uint32_t addr, uint64_t *val_out) {
    bool result = read64(mach, addr, val_out);
    if (!result) {
        mach->cpu.exception = SIGBUS;
    }
    return result;
}

bool write64_check(struct machine *mach, uint32_t addr, uint64_t val) {
    bool result = write64(mach, addr, val);
    if (!result) {
        mach->cpu.exception = SIGBUS;
    }
    return result;
}

uint8_t moxie_var_read_bls_area(struct machine *mach, uint32_t address,
                                bls_area_t *dest, bool wantWrite) {
    uint32_t pointer;
    uint32_t size;
    if (!read32_check(mach, address, &pointer)) {
        return 0;
    }
    if (!read32_check(mach, address + 4, &size)) {
        return 0;
    }
    dest->length = size;
    dest->buffer =
        (uint8_t *)physaddr_check(mach, pointer, dest->length, wantWrite);
    if (dest->buffer == NULL) {
        return 0;
    }
    return 1;
}

uint8_t moxie_var_write_bls_area_length(struct machine *mach, uint32_t address,
                                        size_t length) {
    if (!write32_check(mach, address + 4, length)) {
        return 0;
    }
    return 1;
}

uint8_t moxie_var_read_crypto_handle(struct machine *mach, uint32_t address,
                                     uint32_t *dest) {
    if (!read32_check(mach, address, dest)) {
        return 0;
    }
    return 1;
}

uint8_t moxie_var_write_crypto_handle(struct machine *mach, uint32_t address,
                                      uint32_t src) {
    if (!write32_check(mach, address, src)) {
        return 0;
    }
    return 1;
}
