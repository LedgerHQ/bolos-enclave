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
#include "portable_msg.h"
#include "portable_transient_context.h"

extern int get_free_execution_slot();
extern int dump_machine_state(uint32_t slotIndex, uint8_t *out,
                              uint32_t length);
extern void write_u32_be(unsigned char *buffer, uint32_t value);
extern bolos_transient_context_t bolosTransientContext;

/*
* bls_continuation_supported
* Output:
* int
*/
void moxie_bls_continuation_supported(struct machine *mach) {
    mach->cpu.regs[MOXIE_R0] = 1;
}

/*
* bls_set_continuation
* $r0 -- addr void*
* $r1 -- length size_t
* Output:
* void
*/
void moxie_bls_set_continuation(struct machine *mach) {
    uint32_t length = mach->cpu.regs[MOXIE_R1];
    uint8_t *buffer = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R0],
                                                length, false);
    int slot = get_free_execution_slot();
    if (slot < 0) {
        printf("No free execution slot\n");
        mach->cpu.exception = SIGBUS;
    } else {
        uint32_t blobLength;
        uint8_t *dest = bolosTransientContext.outBuffer;
        dest[0] = STATUS_CODE_EXEC_SUSPENDED;
        write_u32_be(dest + 1, slot + 1);
        blobLength = dump_machine_state(slot, dest + 1 + 4 + 4 + 4,
                                        bolosTransientContext.outLengthMax - 1 -
                                            4 - 4 - 4);
        if (blobLength == 0) {
            printf("Failed to retrieve machine state\n");
            bolosTransientContext.execSlots[slot].busy = false;
            mach->cpu.exception = SIGBUS;
        } else {
            write_u32_be(dest + 1 + 4, blobLength);
            if (buffer != NULL) {
                if (length > bolosTransientContext.outLengthMax - 1 - 4 - 4 -
                                 4 - blobLength) {
                    printf("Response too long %d max %d\n", length,
                           bolosTransientContext.outLengthMax - 1 - 4 - 4 - 4 -
                               blobLength);
                    bolosTransientContext.execSlots[slot].busy = false;
                    mach->cpu.exception = SIGBUS;
                }
            } else {
                length = 0;
            }
            write_u32_be(dest + 1 + 4 + 4, length);
            if (length != 0) {
                memmove(dest + 1 + 4 + 4 + 4 + blobLength, buffer, length);
            }
            bolosTransientContext.outLength =
                1 + 4 + 4 + 4 + blobLength + length;
            mach->cpu.exception = SIGSUSPEND;
        }
    }
}
