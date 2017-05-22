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
* bls_time_supported
* Output:
* int
*/
void moxie_bls_time_supported(struct machine *mach) {
    int status = sgx_open_pse();
    if (status) {
        sgx_close_pse();
    }
    mach->cpu.regs[MOXIE_R0] = status;
}

/*
* bls_time_delta
* $r0 -- referenceOut uint8_t*
* $r1 -- referenceOutLength size_t
* $r2 -- delta uint64_t*
* $r3 -- trusted uint8_t*
* Output:
* int
*/
void moxie_bls_time_delta(struct machine *mach) {
    uint32_t status = 0;
    uint8_t *referenceOut;
    uint32_t referenceOutLength = mach->cpu.regs[MOXIE_R1];
    uint8_t *out;
    sgx_time_t currentTime;
    sgx_time_source_nonce_t nonce;
    int ret;
    if (referenceOutLength < sizeof(sgx_time_source_nonce_t)) {
        printf("Invalid reference\n");
        goto end;
    }
    referenceOut = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R0],
                                             referenceOutLength, true);
    if (referenceOut == NULL) {
        printf("Invalid reference\n");
        goto end;
    }
    memmove((uint8_t *)&nonce, referenceOut, sizeof(sgx_time_source_nonce_t));
    if (!sgx_open_pse()) {
        printf("Failed to access service\n");
        goto end;
    }
    ret = sgx_get_trusted_time(&currentTime, &nonce);
    if (ret != SGX_SUCCESS) {
        printf("Error reported by API\n");
        goto end;
    }
    memmove(referenceOut, (uint8_t *)&nonce, sizeof(sgx_time_source_nonce_t));

    write64_check(mach, mach->cpu.regs[MOXIE_R2], currentTime);

    out = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R3], 1, true);
    if (out == NULL) {
        printf("Invalid trusted reference\n");
        goto end;
    }
    *out = 0x01;

    status = 1;

end:
    mach->cpu.regs[MOXIE_R0] = status;
}

/*
* bls_time
* $r0 -- time uint64_t*
* $r1 -- trusted uint8_t*
* Output:
* int
*/
void moxie_bls_time(struct machine *mach) {
    // TODO : go through a proxy, report untrusted
    mach->cpu.regs[MOXIE_R0] = 0;
}
