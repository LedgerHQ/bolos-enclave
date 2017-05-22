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
#include <errno.h>
#include "bolos.h"
#include "machine.h"
#include "moxie_swi_common.h"

#include "sgx_pse.h"
#include "sgx_tae_service.h"

/*
* bls_antireplay_supported
* Output:
* int
*/
void moxie_bls_antireplay_supported(struct machine *mach) {
    int status = sgx_open_pse();
    if (status) {
        sgx_close_pse();
    }
    mach->cpu.regs[MOXIE_R0] = status;
}

/*
* bls_antireplay_create
* $r0 -- referenceOut uint8_t*
* $r1 -- referenceOutLength size_t
* Output:
* int
*/
void moxie_bls_antireplay_create(struct machine *mach) {
    uint32_t status = 0;
    uint8_t *referenceOut;
    uint32_t referenceLength = mach->cpu.regs[MOXIE_R1];
    sgx_mc_uuid_t counterReference;
    uint32_t counterValue;
    int ret;
    if (referenceLength < sizeof(sgx_mc_uuid_t)) {
        printf("Output buffer length too small\n");
        goto end;
    }
    referenceOut = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R0],
                                             referenceLength, true);
    if (referenceOut == NULL) {
        printf("Invalid output buffer\n");
        goto end;
    }
    if (!sgx_open_pse()) {
        printf("Failed to access service\n");
        goto end;
    }
    ret = sgx_create_monotonic_counter(&counterReference, &counterValue);
    if (ret != SGX_SUCCESS) {
        printf("Error reported by API\n");
        goto end;
    }
    memmove(referenceOut, (uint8_t *)&counterReference, sizeof(sgx_mc_uuid_t));
    status = sizeof(sgx_mc_uuid_t);
end:
    mach->cpu.regs[MOXIE_R0] = status;
}

/*
* bls_antireplay_query
* $r0 -- reference uint8_t*
* $r1 -- referenceLength size_t
* $r2 -- value uint32_t*
* Output:
* int
*/
void moxie_bls_antireplay_query(struct machine *mach) {
    uint32_t status = 0;
    uint8_t *reference;
    uint32_t referenceLength = mach->cpu.regs[MOXIE_R1];
    sgx_mc_uuid_t counterReference;
    uint32_t counterValue;
    int ret;
    if (referenceLength != sizeof(sgx_mc_uuid_t)) {
        printf("Invalid reference\n");
        goto end;
    }
    reference = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R0],
                                          referenceLength, false);
    if (reference == NULL) {
        printf("Invalid reference\n");
        goto end;
    }
    memmove((uint8_t *)&counterReference, reference, sizeof(sgx_mc_uuid_t));
    if (!sgx_open_pse()) {
        printf("Failed to access service\n");
        goto end;
    }
    ret = sgx_read_monotonic_counter(&counterReference, &counterValue);
    if (ret != SGX_SUCCESS) {
        printf("Error reported by API\n");
        goto end;
    }
    if (!write32_check(mach, mach->cpu.regs[MOXIE_R2], counterValue)) {
        printf("Invalid value pointer\n");
        goto end;
    }
    status = 1;
end:
    mach->cpu.regs[MOXIE_R0] = status;
}

/*
* bls_antireplay_increase
* $r0 -- reference uint8_t*
* $r1 -- referenceLength size_t
* Output:
* int
*/
void moxie_bls_antireplay_increase(struct machine *mach) {
    uint32_t status = 0;
    uint8_t *reference;
    uint32_t referenceLength = mach->cpu.regs[MOXIE_R1];
    sgx_mc_uuid_t counterReference;
    uint32_t counterValue;
    int ret;
    if (referenceLength != sizeof(sgx_mc_uuid_t)) {
        printf("Invalid reference\n");
        goto end;
    }
    reference = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R0],
                                          referenceLength, false);
    if (reference == NULL) {
        printf("Invalid reference\n");
        goto end;
    }
    memmove((uint8_t *)&counterReference, reference, sizeof(sgx_mc_uuid_t));
    if (!sgx_open_pse()) {
        printf("Failed to access service\n");
        goto end;
    }
    ret = sgx_increment_monotonic_counter(&counterReference, &counterValue);
    if (ret != SGX_SUCCESS) {
        printf("Error reported by API\n");
        goto end;
    }
    status = 1;
end:
    mach->cpu.regs[MOXIE_R0] = status;
}

/*
* bls_antireplay_delete
* $r0 -- reference uint8_t*
* $r1 -- referenceLength size_t
* Output:
* int
*/
void moxie_bls_antireplay_delete(struct machine *mach) {
    uint32_t status = 0;
    uint8_t *reference;
    uint32_t referenceLength = mach->cpu.regs[MOXIE_R1];
    sgx_mc_uuid_t counterReference;
    uint32_t counterValue;
    int ret;
    if (referenceLength != sizeof(sgx_mc_uuid_t)) {
        printf("Invalid reference\n");
        goto end;
    }
    reference = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R0],
                                          referenceLength, false);
    if (reference == NULL) {
        printf("Invalid reference\n");
        goto end;
    }
    memmove((uint8_t *)&counterReference, reference, sizeof(sgx_mc_uuid_t));
    if (!sgx_open_pse()) {
        printf("Failed to access service\n");
        goto end;
    }
    ret = sgx_destroy_monotonic_counter(&counterReference);
    if (ret != SGX_SUCCESS) {
        printf("Error reported by API\n");
        goto end;
    }
    status = 1;
end:
    mach->cpu.regs[MOXIE_R0] = status;
}
