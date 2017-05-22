#!/bin/bash
git clone https://github.com/bitcoin-core/secp256k1
cd secp256k1
git checkout 119949232a243396ba1462676932a11022592b59
cd src
patch -p0 < ../../patches/secp256k1.patch
cd ..
./autogen.sh
./configure --enable-endomorphism --enable-module-ecdh --enable-module-recovery --enable-experimental --enable-openssl-tests=no
make src/ecmult_static_context.h
cd ..
git clone https://github.com/kmackay/micro-ecc 
cd micro-ecc 
git checkout 14222e062d77f45321676e813d9525f32a88e8fa
patch -p0 < ../patches/uECC.patch
cd ..
wget -qO- https://github.com/jedisct1/libsodium/releases/download/1.0.12/libsodium-1.0.12.tar.gz | tar xvz
cd libsodium-1.0.12
cd src/libsodium
patch -p0 < ../../../patches/libsodium.patch
cd ../..
./configure
cd ../
git clone https://github.com/bitcoin-core/ctaes
cd ctaes
git checkout 003a4acfc273932ab8c2e276cde3b4f3541012dd
cd ..

