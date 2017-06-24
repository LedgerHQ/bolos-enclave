"""
*******************************************************************************
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
********************************************************************************
"""

import os, cffi, subprocess
if os.name == 'nt':
	SGX_INCLUDE = os.environ['SGXSDKINSTALLPATH'] + 'include'
	SGX_LIB = os.environ['SGXSDKINSTALLPATH'] + '\\bin\\win32\\release'
	SGX_BIN = SGX_LIB
else:
	SGX_INCLUDE = '/opt/intel/sgxsdk/include'
	SGX_LIB = '/opt/intel/sgxsdk/lib64'
	SGX_BIN = '/opt/intel/sgxsdk/bin/x64'
subprocess.check_call(["%s/sgx_edger8r" % SGX_BIN, "--untrusted", "BolosSGX.edl", "--search-path", SGX_INCLUDE], cwd="../../tee/Enclave") 
ffibuilder = cffi.FFI()
src = open('../dylib_sgx/bolos_enclave.c', 'r')
ffibuilder.cdef(
	"""

typedef uint64_t bolos_enclave_id_t;
typedef uint32_t bolos_ra_context_t;
typedef uint32_t bolos_status_t;

typedef enum {

	BOLOS_ATTESTATION_KEY_1 = 1,
	BOLOS_ATTESTATION_KEY_2 = 2,

} bolos_attestation_key_t;

#define BOLOS_ENCLAVE_STATUS_OK 0
#define BOLOS_ENCLAVE_STATUS_INVALID_PARAMETER 0xFFFFFFFD
#define BOLOS_ENCLAVE_STATUS_INVALID_SIZE 0xFFFFFFFE
#define BOLOS_ENCLAVE_STATUS_INTERNAL_ERROR 0xFFFFFFFF

#define BOLOS_ENCLAVE_MSG1_SIZE 68

bolos_status_t bolos_enclave_open(char *enclaveName, bool debug, bolos_enclave_id_t *enclaveId);
bolos_status_t bolos_enclave_close(bolos_enclave_id_t enclaveId);

bolos_status_t bolos_enclave_get_extended_epid_group_id(uint32_t *groupId);

bolos_status_t bolos_enclave_create_persistent_context(bolos_enclave_id_t enclaveId, uint8_t *context, uint32_t *contextSize);
bolos_status_t bolos_enclave_set_persistent_context(bolos_enclave_id_t enclaveId, uint8_t *context, uint32_t contextSize);
bolos_status_t bolos_enclave_get_persistent_context(bolos_enclave_id_t enclaveId, uint8_t *context, uint32_t *contextSize);
bolos_status_t bolos_enclave_is_persistent_context_dirty(bolos_enclave_id_t enclaveId, bool *dirty);
bolos_status_t bolos_enclave_clear_persistent_context_dirty_flag(bolos_enclave_id_t enclaveId);

bolos_status_t bolos_enclave_exchange(bolos_enclave_id_t enclaveId, uint8_t *command, uint32_t commandSize, uint8_t *response, uint32_t *responseSize);

bolos_status_t bolos_enclave_ra_init(bolos_enclave_id_t enclaveId, bool openPSESession, uint8_t *msg1, uint32_t *msg1Size, bolos_ra_context_t *raContext);
bolos_status_t bolos_enclave_ra_handshake(bolos_enclave_id_t enclaveId, bolos_ra_context_t raContext, uint8_t *msg2, uint32_t msg2Size, uint8_t *msg3, uint32_t *msg3Size);
bolos_status_t bolos_enclave_ra_get_attestation_key(bolos_enclave_id_t enclaveId, bolos_ra_context_t raContext, bolos_attestation_key_t keyIndex, uint8_t *attestation, uint32_t *attestationSize);
bolos_status_t bolos_enclave_ra_set_personalization_key(bolos_enclave_id_t enclaveId, bolos_ra_context_t raContext, uint8_t *keyBlob, uint32_t keyBlobSize);
bolos_status_t bolos_enclave_ra_close(bolos_enclave_id_t enclaveId, bolos_ra_context_t raContext);

	"""
)
ffibuilder.set_source("_libbolosenclave", src.read(),
	sources=["../../tee/Enclave/BolosSGX_u.c"],
	define_macros=[('CFFI', 1)],
	include_dirs=["../dylib_sgx", SGX_INCLUDE, "../../tee/Enclave"],
	libraries=["sgx_ukey_exchange", "sgx_urts", "sgx_uae_service"],
	library_dirs=[SGX_LIB],
	source_extension='.cpp')
#ffibuilder.compile(verbose=True)

