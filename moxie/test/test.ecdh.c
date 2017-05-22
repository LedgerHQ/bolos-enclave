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

int compare(unsigned char *a, unsigned char *b, size_t size) {
	for (int i=0; i<size; i++) {
		if (a[i] != b[i]) {
			return 0;
		}
	}
	return 1;
} 

int main(int argc, char **argv) {
	bls_ecfp_public_key_t publicKey = {0};
	bls_ecfp_private_key_t privateKey = {0};
        bls_ecfp_public_key_t publicKey2 = {0};
        bls_ecfp_private_key_t privateKey2 = {0};
	unsigned char publicPoint[65];
	unsigned char secret[65];
	unsigned char secret2[65];
	for (int i=0; i<2; i++) {
		int status;
		int curve = (i == 0 ? BLS_CURVE_256K1 : BLS_CURVE_256R1);
		bls_ecdsa_init_private_key(curve, NULL, 0, &privateKey);
		bls_ecdsa_init_public_key(curve, NULL, 0, &publicKey);
		bls_ecfp_generate_pair(curve, &publicKey, &privateKey, NULL);
                bls_ecdsa_init_private_key(curve, NULL, 0, &privateKey2);
                bls_ecdsa_init_public_key(curve, NULL, 0, &publicKey2);
                bls_ecfp_generate_pair(curve, &publicKey2, &privateKey2, NULL);
		bls_ecfp_get_public_component(&publicKey2, publicPoint);
		bls_ecdh(&privateKey, BLS_ECDH_POINT, publicPoint, secret);
                bls_ecfp_get_public_component(&publicKey, publicPoint);
                status = bls_ecdh(&privateKey2, BLS_ECDH_POINT, publicPoint, secret2);
		if (status && compare(secret, secret2, 65)) {
			bls_debug("ECDH point ok\n");
		}
		else {
			bls_debug("ECDH point not ok\n");
		}
                bls_ecfp_get_public_component(&publicKey2, publicPoint);
                bls_ecdh(&privateKey, BLS_ECDH_X, publicPoint, secret);
                bls_ecfp_get_public_component(&publicKey, publicPoint);
                status = bls_ecdh(&privateKey2, BLS_ECDH_X, publicPoint, secret2);
                if (status && compare(secret, secret2, 32)) {
                        bls_debug("ECDH X ok\n");
                }
                else {
                        bls_debug("ECDH X not ok\n");
                }
		if (curve == BLS_CURVE_256K1) {
                	bls_ecfp_get_public_component(&publicKey2, publicPoint);
                	bls_ecdh(&privateKey, BLS_ECDH_HASHED, publicPoint, secret);
                	bls_ecfp_get_public_component(&publicKey, publicPoint);
                	status = bls_ecdh(&privateKey2, BLS_ECDH_HASHED, publicPoint, secret2);
                	if (status && compare(secret, secret2, 32)) {
                        	bls_debug("ECDH hashed ok\n");
                	}
                	else {
                        	bls_debug("ECDH hashed not ok\n");
                	}
		}
	}
}

