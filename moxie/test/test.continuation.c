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

unsigned char do_2() {
	unsigned char test[2];
	bls_copy_input_parameters(test, 0, 1);
	test[1] = test[0] + 0x80;	
	bls_set_continuation(test, 2);
	bls_copy_input_parameters(test, 0, 1);
	return test[0] + test[1];
}

unsigned char do_1() {
	unsigned char x = do_2();
	unsigned char test[1];
	test[0] = x;
	bls_set_continuation(test, 1);
	return x + 2;
}

int main(int argc, char **argv) {
	unsigned char test[1];
	test[0] = do_1();
	bls_set_return(test, 1);
	return 0;
}

