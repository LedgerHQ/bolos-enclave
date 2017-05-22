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
	unsigned char test[10];
	bls_copy_input_parameters(test, 0, 1);
	if (test[0] == 0x01) {
		bls_debug("ok 1\n");
	}
	else {
		bls_debug("ok 2\n");
	}
	test[1] = test[0] * 2;
	bls_set_return(test, 2);
	return 0;
}
