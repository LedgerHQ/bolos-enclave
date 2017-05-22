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
	unsigned char keyData[16];
	unsigned char ivData[8];
	bls_des_key_t key;
	bls_area_t src;
	bls_area_t dest;
	bls_area_t iv;
	unsigned char data[30];
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
	bls_des_init_key(keyData, sizeof(keyData), &key); 
	bls_des(&key, BLS_ENCRYPT | BLS_CHAIN_CBC | BLS_PAD_PKCS5 | BLS_LAST, &src, &dest);
	src.buffer = dest.buffer;
	src.length = dest.length;
	dest.buffer = tmp2;
	dest.length = sizeof(tmp2);
	bls_des(&key, BLS_DECRYPT | BLS_CHAIN_CBC | BLS_PAD_PKCS5 | BLS_LAST, &src, &dest);
	for (i=0; i<sizeof(data); i++) {
		if (data[i] != tmp2[i]) {	
			ok = 0; 
			break;
		}
	}
	if (ok) {
		bls_debug("DES ok\n");
	}
	else {
		bls_debug("DES ko\n");
	}
	tmp2[0] = 0x00;
        src.buffer = data;
        src.length = sizeof(data);
        dest.buffer = tmp;
        dest.length = sizeof(tmp);
	iv.buffer = ivData;
	iv.length = sizeof(ivData);
        bls_rng(keyData, sizeof(keyData));
	bls_rng(ivData, sizeof(ivData));
        bls_des_init_key(keyData, sizeof(keyData), &key);
        bls_des_iv(&key, BLS_ENCRYPT | BLS_CHAIN_CBC | BLS_PAD_PKCS5 | BLS_LAST, &iv, &src, &dest);
        src.buffer = dest.buffer;
        src.length = dest.length;
        dest.buffer = tmp2;
        dest.length = sizeof(tmp2);
        bls_des_iv(&key, BLS_DECRYPT | BLS_CHAIN_CBC | BLS_PAD_PKCS5 | BLS_LAST, &iv, &src, &dest);
        for (i=0; i<sizeof(data); i++) {
                if (data[i] != tmp2[i]) {
                        ok = 0;
                        break;
                }
        }
        if (ok) {
                bls_debug("DES iv ok\n");
        }
        else {
                bls_debug("DES iv ko\n");
        }
}

