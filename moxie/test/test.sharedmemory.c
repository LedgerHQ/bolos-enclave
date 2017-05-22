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

#define ACTION_GET_SIZE 0x00
#define ACTION_READ 0x01
#define ACTION_WRITE 0x02

int main(int argc, char **argv) {
	unsigned char data[256];
	unsigned char data2[256];	
	bls_copy_input_parameters(data, 0, 1);	
	uint32_t value;
	switch(data[0]) {

		case ACTION_GET_SIZE:
			value = bls_sharedmemory_get_size();
			data2[0] = value >> 24;
			data2[1] = value >> 16;
			data2[2] = value >> 8;
			data2[3] = value;
			bls_set_return(data2, 4);
			break;

		case ACTION_READ:
			bls_debug("read\n");
			data2[0] = 'A';
			data2[1] = 'B';
			data2[2] = 'C';
			data2[3] = '\0';
			bls_debug(data2);
			bls_debug("\n");
			bls_sharedmemory_read(data2, 0, 10);
			bls_debug("done\n");
			bls_set_return(data2, 10);
			break;

		case ACTION_WRITE:
			for (value = 0; value < 10; value++) {
				data[value] = value;
			}
			bls_debug("write\n");
			bls_sharedmemory_write(data, 0, 10);
			bls_debug("done\n");
			bls_set_return(data, 0);
			break;

		default:
			bls_debug("Unsupported action\n");
			break;

	}
}

