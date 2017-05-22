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
#include <stdlib.h>
#include <stdbool.h>
#include "sgx_tae_service.h"

static bool pse_session_opened = false;

#define MAX_BUSY_RETRY 2

int sgx_open_pse() {
    int ret;
    int busy_retry = MAX_BUSY_RETRY;
    if (pse_session_opened) {
        return 1;
    }
    do {
        ret = sgx_create_pse_session();
    } while ((ret == SGX_ERROR_BUSY) && (busy_retry--));
    if (ret == SGX_SUCCESS) {
        pse_session_opened = true;
        return 1;
    }
    return 0;
}

int sgx_close_pse() {
    int ret;
    if (!pse_session_opened) {
        return 1;
    }
    ret = sgx_close_pse_session();
    if (ret == SGX_SUCCESS) {
        pse_session_opened = false;
        return 1;
    }
    return 0;
}

void sgx_reset_pse() {
    pse_session_opened = false;
}
