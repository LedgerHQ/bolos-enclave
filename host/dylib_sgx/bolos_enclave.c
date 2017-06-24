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

#include "bolos_enclave.h"
#include "sgx_urts.h"
#include "sgx_ukey_exchange.h"
#include "sgx_uae_service.h"
#include "BolosSGX_u.h"

#ifndef CFFI
#ifndef _MSC_VER
#define EXPORTED __attribute__((__visibility__("default")))
#else
#define EXPORTED  __declspec(dllexport)
#endif
#else
#define EXPORTED
#endif

// OCALLs

EXPORTED void debug(const char *str) {
	printf("%s", str);
}

EXPORTED void debugChar(char ch) {
	printf("%c", ch);
}

// /OCALLs


EXPORTED bolos_status_t bolos_enclave_open(char *enclaveName, bool debug, bolos_enclave_id_t *enclaveId) {
	sgx_status_t status = SGX_ERROR_UNEXPECTED;
	sgx_launch_token_t token = { 0 };
	int updated = 0;
	status = sgx_create_enclave(enclaveName, (debug ? 1 : 0), &token, &updated, enclaveId, NULL);
	return (bolos_status_t)status;
}
EXPORTED bolos_status_t bolos_enclave_close(bolos_enclave_id_t enclaveId) {
	sgx_status_t status = SGX_ERROR_UNEXPECTED;
	status = sgx_destroy_enclave(enclaveId);
	return (bolos_status_t)status;
}
EXPORTED bolos_status_t bolos_enclave_get_extended_epid_group_id(uint32_t *groupId) {
	sgx_status_t status = SGX_ERROR_UNEXPECTED;
	status = sgx_get_extended_epid_group_id(groupId);
	return (bolos_status_t)status;
}
EXPORTED bolos_status_t bolos_enclave_create_persistent_context(bolos_enclave_id_t enclaveId, uint8_t *context, uint32_t *contextSize) {
	sgx_status_t status = SGX_ERROR_UNEXPECTED;
	uint32_t result = 0;
	status = createPersistentContext(enclaveId, &result, context, *contextSize);
	if (status != SGX_SUCCESS) {
		goto end;
	}
	if (result == 0) {
		status = SGX_ERROR_UNEXPECTED;
		goto end;
	}
	*contextSize = result;
end:
	return (bolos_status_t)status;
}
EXPORTED bolos_status_t bolos_enclave_set_persistent_context(bolos_enclave_id_t enclaveId, uint8_t *context, uint32_t contextSize) {
	sgx_status_t status = SGX_ERROR_UNEXPECTED;
	uint32_t result = 0;
	status = setPersistentContext(enclaveId, &result, context, contextSize);
	if (status != SGX_SUCCESS) {
		goto end;
	}
	if (result == 0) {
		status = SGX_ERROR_UNEXPECTED;
		goto end;
	}
end:
	return (bolos_status_t)status;
}
EXPORTED bolos_status_t bolos_enclave_get_persistent_context(bolos_enclave_id_t enclaveId, uint8_t *context, uint32_t *contextSize) {
	sgx_status_t status = SGX_ERROR_UNEXPECTED;
	uint32_t result = 0;
	status = getPersistentContext(enclaveId, &result, context, *contextSize);
	if (status != SGX_SUCCESS) {
		goto end;
	}
	if (result == 0) {
		status = SGX_ERROR_UNEXPECTED;
		goto end;
	}
	*contextSize = result;
end:
	return (bolos_status_t)status;
}
EXPORTED bolos_status_t bolos_enclave_is_persistent_context_dirty(bolos_enclave_id_t enclaveId, bool *dirty) {
	sgx_status_t status = SGX_ERROR_UNEXPECTED;
	uint32_t result = 0;
	status = isPersistentContextDirty(enclaveId, &result);
	if (status != SGX_SUCCESS) {
		goto end;
	}
	*dirty = (result != 0);
end:
	return (bolos_status_t)status;
}
EXPORTED bolos_status_t bolos_enclave_clear_persistent_context_dirty_flag(bolos_enclave_id_t enclaveId) {
	sgx_status_t status = SGX_ERROR_UNEXPECTED;
	status = clearPersistentContextDirty(enclaveId);
	return (bolos_status_t)status;
}
EXPORTED bolos_status_t bolos_enclave_exchange(bolos_enclave_id_t enclaveId, uint8_t *command, uint32_t commandSize, uint8_t *response, uint32_t *responseSize) {
	sgx_status_t status = SGX_ERROR_UNEXPECTED;
	uint32_t result = 0;
	status = exchange(enclaveId, &result, command, commandSize, response, *responseSize);
	if (status != SGX_SUCCESS) {
		goto end;
	}
	*responseSize = result;
end:
	return (bolos_status_t)status;
}
EXPORTED bolos_status_t bolos_enclave_ra_init(bolos_enclave_id_t enclaveId, bool openPSESession, uint8_t *msg1, uint32_t *msg1Size, bolos_ra_context_t *raContext) {
	sgx_status_t status = SGX_ERROR_UNEXPECTED;
	sgx_status_t appStatus;
	if (*msg1Size < sizeof(sgx_ra_msg1_t)) {
		status = (sgx_status_t)BOLOS_ENCLAVE_STATUS_INVALID_SIZE;
		goto end;
	}		
	status = initRA(enclaveId, &appStatus, openPSESession, raContext);
	if (status != SGX_SUCCESS) {
		goto end;
	}
	if (appStatus != SGX_SUCCESS) {
		status = appStatus;
		goto end;
	}
	status = sgx_ra_get_msg1(*raContext, enclaveId, sgx_ra_get_ga, (sgx_ra_msg1_t*)msg1);
	if (status != SGX_SUCCESS) {
		goto end;
	}
	*msg1Size = sizeof(sgx_ra_msg1_t);
end:
	return (bolos_status_t)status;
}
EXPORTED bolos_status_t bolos_enclave_ra_handshake(bolos_enclave_id_t enclaveId, bolos_ra_context_t raContext, uint8_t *msg2, uint32_t msg2Size, uint8_t *msg3, uint32_t *msg3Size) {
	sgx_status_t status = SGX_ERROR_UNEXPECTED;
	sgx_ra_msg3_t *msg3Local = NULL;
	uint32_t msg3SizeLocal;
	status = sgx_ra_proc_msg2(raContext, enclaveId, sgx_ra_proc_msg2_trusted, sgx_ra_get_msg3_trusted, (sgx_ra_msg2_t*)msg2, msg2Size, &msg3Local, &msg3SizeLocal);
	if (status != SGX_SUCCESS) {
		goto end;
	}
	if (*msg3Size < msg3SizeLocal) {
		*msg3Size = msg3SizeLocal;
		status = (sgx_status_t)BOLOS_ENCLAVE_STATUS_INVALID_SIZE;
		free(msg3Local);
		goto end;
	}
	*msg3Size = msg3SizeLocal;
	memmove(msg3, msg3Local, msg3SizeLocal);
	free(msg3Local);
end:
	return (bolos_status_t)status;
}
EXPORTED bolos_status_t bolos_enclave_ra_get_attestation_key(bolos_enclave_id_t enclaveId, bolos_ra_context_t raContext, bolos_attestation_key_t keyIndex, uint8_t *attestation, uint32_t *attestationSize) {
	sgx_status_t status = SGX_ERROR_UNEXPECTED;
	uint32_t result = 0;	
	if ((keyIndex != BOLOS_ATTESTATION_KEY_1) && (keyIndex != BOLOS_ATTESTATION_KEY_2)) {
		status = (sgx_status_t)BOLOS_ENCLAVE_STATUS_INVALID_PARAMETER;
		goto end;
	}
	status = getAttestationKeyRA(enclaveId, &result, raContext, keyIndex, attestation, *attestationSize);
	if (status != SGX_SUCCESS) {
		goto end;
	}
	if (result == 0) {
		status = (sgx_status_t)BOLOS_ENCLAVE_STATUS_INVALID_SIZE;		
	}
	*attestationSize = result;
end:
	return (bolos_status_t)status;
}
EXPORTED bolos_status_t bolos_enclave_ra_set_personalization_key(bolos_enclave_id_t enclaveId, bolos_ra_context_t raContext, uint8_t *keyBlob, uint32_t keyBlobSize) {
	sgx_status_t status = SGX_ERROR_UNEXPECTED;
	uint32_t result = 0;	
	status = setPersonalizationKeyRA(enclaveId, &result, raContext, keyBlob, keyBlobSize);
	if (status != SGX_SUCCESS) {			
		goto end;
	}
	if (result == 0) {
		status = (sgx_status_t)BOLOS_ENCLAVE_STATUS_INTERNAL_ERROR;
	}
end:
	return (bolos_status_t)status;
}
EXPORTED bolos_status_t bolos_enclave_ra_close(bolos_enclave_id_t enclaveId, bolos_ra_context_t raContext) {
	sgx_status_t status = SGX_ERROR_UNEXPECTED;
	sgx_status_t appStatus;
	status = closeRA(enclaveId, &appStatus, raContext);
	if (status != SGX_SUCCESS) {
		goto end;
	}
	if (appStatus != SGX_SUCCESS) {
		status = appStatus;
	}
end:
	return (bolos_status_t)status;
}

