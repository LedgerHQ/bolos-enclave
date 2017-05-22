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
	bls_rsa_keypair_data_t keypairData = { 0 };
	bls_rsa_abstract_public_key_t publicKey = { 0 };
	bls_rsa_abstract_private_key_t privateKey = { 0 };
	unsigned char exponent[1];
	unsigned char modulus[512];
	unsigned char privateExponent[512];
	unsigned char srcBuffer[10];
	unsigned char destBuffer[200];
	unsigned char destBuffer2[200];
	unsigned char ok = 0; 
	bls_area_t src;
	bls_area_t dest;
	int i;
	exponent[0] = 0x03;
	keypairData.publicExponent = exponent;
	keypairData.publicExponentSize = 1;
	bls_rsa_init_public_key(&keypairData, &publicKey);
	bls_rsa_init_private_key(NULL, &privateKey);
	keypairData.modulus = modulus;
	keypairData.modulusSize = sizeof(modulus);
	keypairData.privateExponent = privateExponent;
	keypairData.privateExponentSize = sizeof(privateExponent);
	bls_rsa_generate_keypair(1024, &privateKey, &publicKey, &keypairData);	
	bls_debug("Generated\n");
	// Test encryption
	for (i=0; i<sizeof(srcBuffer); i++) {
		srcBuffer[i] = i;
	}
	src.buffer = srcBuffer;
	src.length = sizeof(srcBuffer);
	dest.buffer = destBuffer;
	dest.length = sizeof(destBuffer);
	if (!bls_rsa_pub(&publicKey, BLS_ENCRYPT | BLS_PAD_PKCS1_1o5 | BLS_LAST, 0, &src, &dest)) {
		bls_debug("bls_rsa_pub failed\n");
	}
	src.buffer = dest.buffer;
	src.length = dest.length - 10;
	dest.buffer = destBuffer2;
	dest.length = sizeof(destBuffer2);
	if (!bls_rsa_priv(&privateKey, BLS_DECRYPT | BLS_PAD_PKCS1_1o5, 0, &src, &dest)) {
		bls_debug("bls_rsa_priv failed\n");
	}
	src.buffer = destBuffer + src.length;
	src.length = 10;
	dest.buffer = destBuffer2 + dest.length;
	dest.length = sizeof(destBuffer2) - dest.length;
        if (!bls_rsa_priv(&privateKey, BLS_DECRYPT | BLS_PAD_PKCS1_1o5 | BLS_LAST, 0, &src, &dest)) {
                bls_debug("bls_rsa_priv failed\n");
        } 
	ok = (dest.length != 0);
	for (i=0; i<dest.length; i++) {
		if (srcBuffer[i] != destBuffer2[i]) {
			bls_debug("fail\n");
			ok = 0;
			break;
		}
	}
	if (ok) {
		bls_debug("encrypt/decrypt ok\n");
	}
	// Test signature
        src.buffer = srcBuffer;
        src.length = sizeof(srcBuffer);
        dest.buffer = destBuffer;
        dest.length = sizeof(destBuffer);
        if (!bls_rsa_priv(&privateKey, BLS_SIGN | BLS_PAD_PSS | BLS_LAST, BLS_SHA256, &src, &dest)) {
                bls_debug("bls_rsa_priv_sign failed\n");
        }
        src.buffer = src.buffer;
        src.length = src.length - 5;
        if (!bls_rsa_pub(&publicKey, BLS_VERIFY | BLS_PAD_PSS, BLS_SHA256, &src, &dest)) {
                bls_debug("bls_rsa_pub_sign failed\n");
        }
        src.buffer = src.buffer + src.length;
        src.length = 5;
        if (!bls_rsa_pub(&publicKey, BLS_VERIFY | BLS_PAD_PSS | BLS_LAST, BLS_SHA256, &src, &dest)) {
                bls_debug("bls_rsa_pub_sign failed\n");
        }
	else {
		bls_debug("Signature verified\n");
	}
	bls_debug("end\n");
}

