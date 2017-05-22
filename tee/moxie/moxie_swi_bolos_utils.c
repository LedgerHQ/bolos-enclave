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

/*
* bls_debug
* $r0 -- text char*
* Output:
* void
*/
void moxie_bls_debug(struct machine *mach) {
    uint8_t *buffer = physaddr_check(mach, mach->cpu.regs[MOXIE_R0], 1, false);
    if (buffer != NULL) {
#ifdef SGX
        screen_printf(buffer);
#else
        printf("%s", buffer);
#endif
    }
}
