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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "portable_persistent_context.h"
#include "platform_al.h"

extern bolos_persistent_context_t persistentContext;
extern bool persistentContextSet;
extern bool persistentContextDirty;

void platform_erase_persistent_context(void) {
    platform_secure_memset0(&persistentContext,
                            sizeof(bolos_persistent_context_t));
}

bool platform_read_persistent_context(
    bolos_persistent_context_t *persistentContextParam) {
    if (!persistentContextSet) {
        return false;
    }
    memmove((uint8_t *)persistentContextParam, (uint8_t *)&persistentContext,
            sizeof(bolos_persistent_context_t));
    return true;
}

bool platform_write_persistent_context(
    bolos_persistent_context_t *persistentContextParam) {
    if (!persistentContextSet) {
        return false;
    }
    memmove((uint8_t *)&persistentContext, (uint8_t *)persistentContextParam,
            sizeof(bolos_persistent_context_t));
    persistentContextDirty = true;
    return true;
}

bool platform_create_persistent_context() {
    return true;
}
