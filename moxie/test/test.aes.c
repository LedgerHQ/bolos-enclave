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
	uint32_t i;
	unsigned char keyData[32];
	unsigned char ivData[16];
	bls_aes_key_t key;
	bls_area_t src;
	bls_area_t dest;
	bls_area_t iv;
	unsigned char data[32];
	unsigned char tmp[100];
	unsigned char tmp2[100];
	unsigned char ok = 1;
	for (i=0; i<sizeof(data); i++) {
		data[i] = i;
	}
	src.buffer = data;
	src.length = sizeof(data);
	dest.buffer = tmp;
	dest.length = sizeof(tmp); 
	bls_rng(keyData, sizeof(keyData));
	if (bls_aes_init_key(keyData, sizeof(keyData), &key)) {
		bls_debug("AES init ok\n");
	}
	if (bls_aes(&key, BLS_ENCRYPT | BLS_CHAIN_ECB | BLS_PAD_NONE | BLS_LAST, &src, &dest)) {
		bls_debug("AES encrypt ok\n");
	}
	src.buffer = dest.buffer;
	src.length = dest.length;
	dest.buffer = tmp2;
	dest.length = sizeof(tmp2);
	if (bls_aes(&key, BLS_DECRYPT | BLS_CHAIN_ECB | BLS_PAD_NONE | BLS_LAST, &src, &dest)) {
		bls_debug("AES decrypt ok\n");
	}
	for (i=0; i<sizeof(data); i++) {
		if (data[i] != tmp2[i]) {	
			ok = 0; 
			break;
		}
	}
	if (ok) {
		bls_debug("AES ok\n");
	}
	else {
		bls_debug("AES ko\n");
	}
}

