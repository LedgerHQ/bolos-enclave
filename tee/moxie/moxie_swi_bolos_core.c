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
#include "portable_msg.h"
#include "portable_transient_context.h"

#define API_LEVEL 1

extern bolos_transient_context_t bolosTransientContext;

/*
* bls_get_input_parameters_length
* Output:
* size_t
*/
void moxie_bls_get_input_parameters_length(struct machine *mach) {
    mach->cpu.regs[MOXIE_R0] = bolosTransientContext.parametersLength;
}

/*
* bls_set_return
* $r0 -- addr void*
* $r1 -- length size_t
* Output:
* void
*/
void moxie_bls_set_return(struct machine *mach) {
    uint32_t length = mach->cpu.regs[MOXIE_R1];
    uint8_t *buffer = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R0],
                                                length, false);
    if (buffer != NULL) {
        if (length > bolosTransientContext.outLengthMax - 1) {
            printf("Response too long %d max %d\n", length,
                   bolosTransientContext.outLengthMax - 1);
            mach->cpu.exception = SIGBUS;
        }
    } else {
        length = 0;
    }
    uint8_t *dest = bolosTransientContext.outBuffer;
    dest[0] = STATUS_CODE_EXEC_OK;
    if (length != 0) {
        memmove(dest + 1, buffer, length);
    }
    bolosTransientContext.outLength = length + 1;
}

/*
* bls_copy_input_parameters
* $r0 -- parameters uint8_t*
* $r1 -- offset uint32_t
* $r2 -- parametersLength size_t
* Output:
* size_t
*/
void moxie_bls_copy_input_parameters(struct machine *mach) {
    uint32_t offset = mach->cpu.regs[MOXIE_R1];
    uint32_t length = mach->cpu.regs[MOXIE_R2];
    if ((offset + length) > bolosTransientContext.parametersLength) {
        printf("Parameter copy overflow\n");
        mach->cpu.exception = SIGBUS;
    } else {
        uint8_t *buffer = (uint8_t *)physaddr_check(
            mach, mach->cpu.regs[MOXIE_R0], length, true);
        if (buffer) {
            memmove(buffer, bolosTransientContext.parameters + offset, length);
            mach->cpu.regs[MOXIE_R0] = length;
        } else {
            printf("Destination buffer overflow\n");
            mach->cpu.exception = SIGBUS;
        }
    }
}

/*
* bls_check_api_level
* Output:
* uint32_t
*/
void moxie_bls_check_api_level(struct machine *mach) {
    mach->cpu.regs[MOXIE_R0] = API_LEVEL;
}

/*
* _exit
* $r0 -- status uint32_t
* Output:
* void
*/
void moxie__exit(struct machine *mach) {
    printf("Request exit %d\n", mach->cpu.regs[MOXIE_R0]);
    mach->cpu.exception = SIGQUIT;
}
