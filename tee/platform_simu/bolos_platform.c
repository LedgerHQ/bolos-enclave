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

#include "machine.h"
#include "portable_msg.h"
#include "portable_persistent_context.h"
#include "portable_transient_context.h"
#include "platform_al.h"
#include "bolos.h"
#include "platform_simu.h"

#define EXPORTED __attribute__((__visibility__("default")))

bolos_persistent_context_t persistentContext;
bool persistentContextSet = false;
bool persistentContextDirty = false;
bool initialized;

uint32_t getPersistentContext(uint8_t *context, uint32_t context_size);

EXPORTED uint32_t createPersistentContext(uint8_t *response,
                                          uint32_t response_size) {
    uint32_t result;
    persistentContextSet = false;
    platform_secure_memset0(&persistentContext, sizeof(persistentContext));
    platform_random(persistentContext.deviceWrappingKey,
                    sizeof(persistentContext.deviceWrappingKey));
    result = getPersistentContext(response, response_size);
    if (result) {
        persistentContextSet = true;
        if (!initialized) {
            initialized = bolos_init();
        }
    }
    return result;
}

EXPORTED uint32_t setPersistentContext(uint8_t *context,
                                       uint32_t context_size) {
    if (context_size != sizeof(bolos_persistent_context_t)) {
        return 0;
    }
    memmove((uint8_t *)&persistentContext, context,
            sizeof(bolos_persistent_context_t));

    if (!initialized) {
        initialized = bolos_init();
    }
    persistentContextSet = true;
    return 1;
}

EXPORTED uint32_t getPersistentContext(uint8_t *context,
                                       uint32_t context_size) {
    memmove(context, (uint8_t *)&persistentContext,
            sizeof(bolos_persistent_context_t));
    return sizeof(bolos_persistent_context_t);
}

EXPORTED uint32_t isPersistentContextDirty() {
    return (persistentContextDirty ? 1 : 0);
}

EXPORTED void clearPersistentContextDirty() {
    persistentContextDirty = false;
}

EXPORTED uint32_t exchange(uint8_t *command, uint32_t command_size,
                           uint8_t *response, uint32_t response_size) {
    bolos_exec_status_t status;
    uint32_t outLength;
    simu_context_t simuContext;
    if (!persistentContextSet) {
        return 0;
    }
    simuContext.responseBuffer = response;
    simuContext.responseLength = response_size;
    status =
        bolos_handle_message(&simuContext, command, command_size, &outLength);
    if (status == BOLOS_EXEC_OK) {
        return outLength;
    }
    return 0;
}
