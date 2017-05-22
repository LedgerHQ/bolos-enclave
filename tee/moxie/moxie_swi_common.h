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
#include "machine.h"

#define WIDE

#include "bolos_core.h"
#include "bolos_crypto_common.h"

uint8_t *physaddr_check(struct machine *mach, uint32_t addr, size_t objLen,
                        bool wantWrite);
bool read8_check(struct machine *mach, uint32_t addr, uint8_t *val_out);
bool write8_check(struct machine *mach, uint32_t addr, uint8_t val);
bool read32_check(struct machine *mach, uint32_t addr, uint32_t *val_out);
bool write32_check(struct machine *mach, uint32_t addr, uint32_t val);
bool read64_check(struct machine *mach, uint32_t addr, uint64_t *val_out);
bool write64_check(struct machine *mach, uint32_t addr, uint64_t val);

uint8_t moxie_var_read_bls_area(struct machine *mach, uint32_t address,
                                bls_area_t *dest, bool wantWrite);
uint8_t moxie_var_write_bls_area_length(struct machine *mach, uint32_t address,
                                        size_t length);
uint8_t moxie_var_read_crypto_handle(struct machine *mach, uint32_t address,
                                     uint32_t *dest);
uint8_t moxie_var_write_crypto_handle(struct machine *mach, uint32_t address,
                                      uint32_t src);

uint8_t moxie_var_read_rsa_keypair_data(struct machine *mach, uint32_t address,
                                        bls_rsa_keypair_data_t *dest,
                                        bool wantWrite);
uint8_t moxie_var_write_rsa_keypair_data_lengths(struct machine *mach,
                                                 uint32_t address,
                                                 bls_rsa_keypair_data_t *src);

void moxie_swi_crypto_init(void);
void moxie_swi_crypto_cleanup(void);

void moxie_swi_shared_memory_init(void);
void moxie_swi_shared_memory_cleanup(void);
