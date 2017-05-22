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

#ifndef __BOLOS_H__

#define __BOLOS_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef SGX
#include <assert.h>
#include "BolosSGX_t.h"
#include "bolos_printf.h"
#ifdef SGX_DEBUG
#define printf screen_printf
#else
#define printf
#endif
#endif

enum bolos_exec_status_e {
    BOLOS_EXEC_OK = 1,
    BOLOS_EXEC_UNSUPPORTED,
    BOLOS_EXEC_INVALID_ARGUMENTS,
    BOLOS_EXEC_OUT_OF_MEMORY,
    BOLOS_EXEC_INTERNAL,
};
typedef enum bolos_exec_status_e bolos_exec_status_t;

bool bolos_init(void);
bool bolos_uninit(void);
bolos_exec_status_t bolos_handle_message(void *platformContext, uint8_t *buffer,
                                         uint32_t length, uint32_t *outLength);

#endif
