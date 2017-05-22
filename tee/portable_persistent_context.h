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

#ifndef __PORTABLE_PERSISTENT_CONTEXT_H__

#define __PORTABLE_PERSISTENT_CONTEXT_H__

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include "portable_cx.h"
#include "sodium.h"

typedef struct bolos_persistent_context_s {
    uint8_t deviceWrappingKey[crypto_secretbox_KEYBYTES];
    cx_ecfp_private_key_t endorsement_private_key1;
    uint8_t endorsement_private_key1_hash[32];
    cx_ecfp_private_key_t endorsement_private_key2;
    uint8_t endorsement_key1_certificate[1024];
    uint16_t endorsement_key1_certificate_length;
    uint8_t endorsement_key2_certificate[1024];
    uint16_t endorsement_key2_certificate_length;
} bolos_persistent_context_t;

#endif
