all:	test.aes test.des test.ecdh test.ecdsa test.endorsement_init test.endorsement_run test.hash test.hmac test.init test.pbkdf2 test.rsa test.schnorr test.sodium  test.wrapping test.antireplay test.sharedmemory test.continuation test.derive_btc test.antireplay test.time_direct test.time_delta

%:	%.c
	moxiebox-gcc -O2 -mel $< -I../api -L../runtime -lbolos -o $@

clean:
	rm -rf test.aes test.des test.ecdh test.ecdsa test.endorsement_init test.endorsement_run test.hash test.hmac test.init test.pbkdf2 test.rsa test.schnorr test.sodium test.wrapping test.antireplay test.sharedmemory test.continuation test.derive_btc test.antireplay test.time_direct test.time_delta

