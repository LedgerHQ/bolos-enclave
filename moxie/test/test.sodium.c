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

int test_secretbox() {
	unsigned char nonce[crypto_secretbox_NONCEBYTES];
	unsigned char key[crypto_secretbox_KEYBYTES];
	unsigned char ciphertext[crypto_secretbox_MACBYTES + 4];
	bls_rng(nonce, sizeof(nonce));
	bls_rng(key, sizeof(key));
	int status = crypto_secretbox_easy(ciphertext, "test", 4, nonce, key);
	if (!status) {
		unsigned char decrypted[4];
		if (!crypto_secretbox_open_easy(decrypted, ciphertext, sizeof(ciphertext), nonce, key)) {
			bls_debug("secretbox ok\n");
			return 1;
		}
	}
	bls_debug("secretbox ko\n");
	return 0;
}

int test_auth() {
	unsigned char key[crypto_auth_KEYBYTES];
	unsigned char mac[crypto_auth_BYTES];
	bls_rng(key, sizeof(key));
	int status = crypto_auth(mac, "test", 4, key);
	if (!status) {
		if (!crypto_auth_verify(mac, "test", 4, key)) {
			bls_debug("auth ok\n");
			return 1;
		}
	}
	bls_debug("auth ko\n");
	return 0;
}

int test_box() {
	unsigned char alice_publickey[crypto_box_PUBLICKEYBYTES];
	unsigned char alice_secretkey[crypto_box_SECRETKEYBYTES];
	crypto_box_keypair(alice_publickey, alice_secretkey);

	unsigned char bob_publickey[crypto_box_PUBLICKEYBYTES];
	unsigned char bob_secretkey[crypto_box_SECRETKEYBYTES];
	crypto_box_keypair(bob_publickey, bob_secretkey);

	unsigned char nonce[crypto_box_NONCEBYTES];
	unsigned char ciphertext[crypto_box_MACBYTES + 4];
	bls_rng(nonce, sizeof(nonce));
	int status = crypto_box_easy(ciphertext, "test", 4, nonce, bob_publickey, alice_secretkey);
	if (status == 0) {
		unsigned char decrypted[4];
		if (!crypto_box_open_easy(decrypted, ciphertext, sizeof(ciphertext), nonce, alice_publickey, bob_secretkey)) {
			bls_debug("box ok\n");
			return 1;
		}
	}
	bls_debug("box ko\n");
	return 0;
}

int test_sign() {
	unsigned char pk[crypto_sign_PUBLICKEYBYTES];
	unsigned char sk[crypto_sign_SECRETKEYBYTES];
	crypto_sign_keypair(pk, sk);

	unsigned char signed_message[crypto_sign_BYTES + 4];
	unsigned long signed_message_len;

	int status = crypto_sign(signed_message, &signed_message_len, "TEST", 4, sk);

	if (!status) {
		unsigned char unsigned_message[4];
		unsigned long unsigned_message_len;
		if (!crypto_sign_open(unsigned_message, &unsigned_message_len, signed_message, signed_message_len, pk)) {
			bls_debug("sign ok\n");
			return 1;
		}
	}
	bls_debug("sign ko\n");
	return 0;
}

int test_seal() {
	unsigned char recipient_pk[crypto_box_PUBLICKEYBYTES];
	unsigned char recipient_sk[crypto_box_SECRETKEYBYTES];
	crypto_box_keypair(recipient_pk, recipient_sk);

	unsigned char ciphertext[crypto_box_SEALBYTES + 4];
	int status = crypto_box_seal(ciphertext, "test", 4, recipient_pk);
	if (!status) {
		unsigned char decrypted[4];
		if (!crypto_box_seal_open(decrypted, ciphertext, sizeof(ciphertext), recipient_pk, recipient_sk)) {
			bls_debug("seal ok\n");
			return 1;
		}
	}
	bls_debug("seal ko\n");
	return 0;
}


int main(int argc, char **argv) {
	int test = 0;
	unsigned char buffer[1];
	test += test_secretbox();
	test += test_auth();
	test += test_box();
	test += test_sign();
	test += test_seal();
	if (test == 5) {
		bls_debug("Sodium test ok\n");
	}
	buffer[0] = test;
	bls_set_return(buffer, 1);
}

