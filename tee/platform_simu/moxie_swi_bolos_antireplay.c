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
#include <unistd.h>
#include "bolos.h"
#include "machine.h"
#include "moxie_swi_common.h"
#include "platform_al.h"

/*
* bls_antireplay_supported
* Output:
* int
*/
void moxie_bls_antireplay_supported(struct machine *mach) {
    mach->cpu.regs[MOXIE_R0] = 1;
}

/*
* bls_antireplay_create
* $r0 -- referenceOut uint8_t*
* $r1 -- referenceOutLength size_t
* Output:
* int
*/
void moxie_bls_antireplay_create(struct machine *mach) {
    char path[20];
    uint8_t tmp[4];
    uint32_t status = 0;
    uint32_t length = mach->cpu.regs[MOXIE_R1];
    uint32_t counter = 0;
    uint8_t *referenceOut;
    FILE *out;
    platform_random(tmp, 4);
    sprintf(path, "cntr_%.2X%.2X%.2X%.2X.bin", tmp[0], tmp[1], tmp[2], tmp[3]);
    if (length < strlen(path) + 1) {
        goto end;
    }
    referenceOut =
        (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R0], length, true);
    if (!referenceOut) {
        goto end;
    }
    out = fopen(path, "wb");
    if (out == NULL) {
        goto end;
    }
    if (fwrite(&counter, 1, 4, out) != 4) {
        fclose(out);
        goto end;
    }
    fclose(out);
    memmove(referenceOut, path, strlen(path) + 1);
    status = strlen(path) + 1;
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
    uint32_t length = mach->cpu.regs[MOXIE_R1];
    uint32_t valueAddress = mach->cpu.regs[MOXIE_R2];
    uint32_t counter;
    uint8_t *referenceIn;
    FILE *in;
    referenceIn = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R0],
                                            length, false);
    if ((!referenceIn) || (referenceIn[length - 1] != 0)) {
        goto end;
    }
    in = fopen(referenceIn, "rb");
    if (in == NULL) {
        goto end;
    }
    if (fread(&counter, 1, 4, in) != 4) {
        fclose(in);
        goto end;
    }
    fclose(in);
    if (!write32_check(mach, valueAddress, counter)) {
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
    uint32_t length = mach->cpu.regs[MOXIE_R1];
    uint32_t counter;
    uint8_t *referenceIn;
    FILE *in;
    referenceIn = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R0],
                                            length, false);
    if ((!referenceIn) || (referenceIn[length - 1] != 0)) {
        goto end;
    }
    in = fopen(referenceIn, "rb");
    if (in == NULL) {
        goto end;
    }
    if (fread(&counter, 1, 4, in) != 4) {
        fclose(in);
        goto end;
    }
    fclose(in);
    if (counter == 0xFFFFFFFF) {
        goto end;
    }
    counter++;
    in = fopen(referenceIn, "wb");
    if (in == NULL) {
        goto end;
    }
    if (fwrite(&counter, 1, 4, in) != 4) {
        fclose(in);
        goto end;
    }
    fclose(in);
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
    uint32_t length = mach->cpu.regs[MOXIE_R1];
    uint8_t *referenceIn;
    referenceIn = (uint8_t *)physaddr_check(mach, mach->cpu.regs[MOXIE_R0],
                                            length, false);
    if ((!referenceIn) || (referenceIn[length - 1] != 0)) {
        goto end;
    }
    if (unlink(referenceIn) == 0) {
        status = 1;
    }
end:
    mach->cpu.regs[MOXIE_R0] = status;
}
