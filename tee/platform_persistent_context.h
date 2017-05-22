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

#ifndef __PLATFORM_PERSISTENT_CONTEXT_H__

#define __PLATFORM_PERSISTENT_CONTEXT_H__

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include "portable_cx.h"
#include "portable_persistent_context.h"

bool platform_read_persistent_context(
    bolos_persistent_context_t *persistentContext);
bool platform_write_persistent_context(
    bolos_persistent_context_t *persistentContext);
void platform_erase_persistent_context(void);
bool platform_create_persistent_context(void);

#endif
