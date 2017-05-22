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
#include <time.h>
#include "bolos.h"
#include "machine.h"
#include "moxie_swi_common.h"

/*
* bls_time_supported
* Output:
* int
*/
void moxie_bls_time_supported(struct machine *mach) {
    mach->cpu.regs[MOXIE_R0] = 1;
}

/*
* bls_time_delta
* $r0 -- referenceOut uint8_t*
* $r1 -- referenceOutLength size_t
* $r2 -- delta uint64_t*
* Output:
* int
*/
void moxie_bls_time_delta(struct machine *mach) {
    mach->cpu.regs[MOXIE_R0] = 0;
}

/*
* bls_time
* $r0 -- time uint64_t*
* $r1 -- trusted uint8_t*
* Output:
* int
*/
void moxie_bls_time(struct machine *mach) {
    time_t currentTime = time(NULL);
    write64_check(mach, mach->cpu.regs[MOXIE_R0], currentTime);
    write8_check(mach, mach->cpu.regs[MOXIE_R1], 0);
    mach->cpu.regs[MOXIE_R0] = 1;
}
