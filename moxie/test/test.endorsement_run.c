/*
*******************************************************************************    
*   BOLOS TEE Samples
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
#include "bolos.h"

int main(int argc, char **argv) {
	unsigned char data[500];
	unsigned char dummy[10];
	bls_copy_input_parameters(data, 0, 1);
	bls_debug("start\n");
	if ((data[0] == 0x00) || (data[0] == 0x01)) {
		unsigned char scope = data[0];
		int offset = 0;
		int size = bls_endorsement_get_public_key(scope, data, sizeof(data));
		if (size == 0) {
			bls_debug("Fail endorsement 1\n");
			return 0;
		}
		offset += size;
		int sizeCertif = bls_endorsement_get_certificate(scope, data + offset, sizeof(data) - offset);
		if (sizeCertif == 0) {
			bls_debug("Fail certificate 1\n");
			return 0;
		}
		offset += sizeCertif;
		int codeHashSize = bls_endorsement_get_code_hash(data + offset, sizeof(data) - offset);
		if (codeHashSize == 0) {
			bls_debug("Fail code hash size\n");
			return 0;
		}
		offset += codeHashSize;
		if (scope == 0x00) {
			int appSecretSize = bls_endorsement_key1_get_app_secret(data + offset, sizeof(data) - offset);
			if (appSecretSize == 0) {
				bls_debug("get_app_secret failed\n");
				return 0;
			}
			offset += appSecretSize;
			int signSize = bls_endorsement_key1_sign_data("test", 4, data + offset, sizeof(data) - offset);
			if (signSize == 0) {
				bls_debug("key1_sign_data failed\n");
				return 0;
			}
			offset += signSize;
		}
		else {
			int signSize = bls_endorsement_key2_derive_sign_data("test", 4, data + offset, sizeof(data) - offset);
			if (signSize == 0) {
				bls_debug("key2_sign_data failed\n");
				return 0;
			}
			offset += signSize;
		}
		bls_debug("end\n");
		bls_set_return(data, offset);
	}
}

