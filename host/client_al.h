/*
*******************************************************************************
*   BOLOS TEE
*   (c) 2016, 2017 Ledger
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*   Unless required by applicable law or agreed to in writing, software
*   distributed under the License is distributed on an "AS IS" BASIS,
*   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*   limitations under the License.
********************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

void *platform_init(void);
bool platform_uninit(void *context);
uint32_t platform_exchange(void *context, uint8_t *message, uint32_t size,
                           uint8_t *response, uint32_t responseSize);
void platform_usage(char *name);
int platform_process(void *context, int argc, char **argv,
                     bool *platform_handled);
