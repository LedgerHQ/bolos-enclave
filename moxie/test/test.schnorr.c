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
	bls_ecfp_public_key_t publicKey = {0};
	bls_ecfp_private_key_t privateKey = {0};
	unsigned char tmp[32];
	unsigned char result[32 + 65];
	unsigned char signature[100];
	int signatureLength;
	for (int i=0; i<sizeof(tmp); i++) {
		tmp[i] = i;
	}
	bls_ecdsa_init_private_key(BLS_CURVE_256K1, NULL, 0, &privateKey);
	bls_ecdsa_init_public_key(BLS_CURVE_256K1, NULL, 0, &publicKey);
	bls_ecfp_generate_pair(BLS_CURVE_256K1, &publicKey, &privateKey, result);
	signatureLength = bls_schnorr_sign(&privateKey, BLS_SIGN | BLS_LAST | BLS_RND_RFC6979, BLS_SHA256, tmp, sizeof(tmp), signature);
	int signatureResult = bls_schnorr_verify(&publicKey, BLS_VERIFY | BLS_LAST, BLS_SHA256, tmp, sizeof(tmp), signature);
	if (signatureResult) {
		bls_debug("sign Schnorr OK\n");
	}
	else {
		bls_debug("sign Schnorr failed\n");
	}
	bls_ecfp_get_public_component(&publicKey, result + 32);
	bls_set_return(result, sizeof(result));
}
