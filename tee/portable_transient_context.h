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

#ifndef __PORTABLE_TRANSIENT_CONTEXT_H__

#define __PORTABLE_TRANSIENT_CONTEXT_H__

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stdbool.h>
#include "portable_cx.h"
#include "sodium.h"

typedef struct bolos_exec_slot_s {
    uint8_t stateHash[32];
    uint8_t slotKey[crypto_secretbox_KEYBYTES];
    uint32_t timeout;
    bool busy;
} bolos_exec_slot_t;

typedef struct bolos_transient_context_s {
    uint8_t runningExecCodeHash[32];
    uint8_t sessionWrappingKey[crypto_secretbox_KEYBYTES];
    uint8_t personalizationKey[crypto_secretbox_KEYBYTES];
    bool personalizationKeySet;
    uint8_t *parameters;
    uint32_t parametersLength;
    uint8_t *outBuffer;
    uint32_t outLength;
    uint32_t outLengthMax;
    bool sessionOpened;
    uint8_t tokenPublicKey[65];
    bool tokenPublicKeyUsed;
    uint32_t numExecSlots;
    uint32_t timeoutExecSlot;
    bolos_exec_slot_t *execSlots;
    uint32_t stackSize;
} bolos_transient_context_t;

#endif
