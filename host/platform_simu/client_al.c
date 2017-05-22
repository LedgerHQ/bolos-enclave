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
#include <stdint.h>
#include <stdbool.h>
#include "client_al.h"

extern uint32_t createPersistentContext(uint8_t* response, uint32_t response_size);
extern uint32_t setPersistentContext(uint8_t* context, uint32_t context_size);
extern uint32_t getPersistentContext(uint8_t* context, uint32_t context_size);
extern uint32_t isPersistentContextDirty(void);
extern void clearPersistentContextDirty(void);
extern uint32_t exchange(uint8_t* command, uint32_t command_size, uint8_t* response, uint32_t response_size);

#define CONTEXT_FILE "BolosSimuContext.bin"
#define CONTEXT_FILE_NEW "BolosSimuContextNew.bin"
#define CONTEXT_SIZE 100000

void* platform_init(void) {
	int updated = 0;
	FILE *contextFile;
	uint32_t contextSize;
	uint8_t *context;
	uint32_t status = 0;

	contextFile = fopen(CONTEXT_FILE, "rb");
	if (contextFile == NULL) {
		printf("No context found - creating new\n");
		context = (uint8_t*)malloc(CONTEXT_SIZE);
		status = createPersistentContext(context, CONTEXT_SIZE);
		if (!status) {
			printf("createPersistentContext failed\n");
			free(context);
			return NULL;
		}
		contextFile = fopen(CONTEXT_FILE, "wb");
		fwrite(context, 1, status, contextFile);
		fclose(contextFile);
	}
	else {		
		printf("Reloading context\n");
		fseek(contextFile, 0, SEEK_END);
		contextSize = ftell(contextFile);
		fseek(contextFile, 0, SEEK_SET);
		context = (uint8_t*)malloc(contextSize);
		fread(context, 1, contextSize, contextFile);
		fclose(contextFile);
		status = setPersistentContext(context, contextSize);
		if (!status) {
			printf("setPersistentContext failed\n");
			free(context);
			return NULL;
		}
	}

	return (void*)1;
}

bool platform_uninit(void* context) {
	uint32_t status;
	status = isPersistentContextDirty();
	if (status) {
		uint8_t *context;
		printf("Persistent context is dirty - creating copy\n");
		context = (uint8_t*)malloc(CONTEXT_SIZE);
		status = getPersistentContext(context, CONTEXT_SIZE);
		if (status) {
			FILE *contextFile;
			contextFile = fopen(CONTEXT_FILE_NEW, "wb");
			fwrite(context, 1, status, contextFile);
			fclose(contextFile);
		}
		else {
			printf("getPersistentContext failed\n");
		}
		free(context);
	}

	return true;
}

uint32_t platform_exchange(void* context, uint8_t *message, uint32_t size, uint8_t *response, uint32_t responseSize) {
	return exchange(message, size, response, responseSize);	
}

void platform_usage(char *name) {
}

int platform_process(void *context, int argc, char **argv, bool *platform_handled) {
	*platform_handled = false;
	return 0;
}

