# Ledger BOLOS Enclave

BOLOS Enclave provides a simple, portable and flexible Trusted Computing Base environment for blockchain applications, allowing to run code in a controlled environment and prove the execution on chain (See [Oraclize](https://medium.com/provable/the-random-datasource-chapter-2-779946e54f49), with common mechanisms for all Ledger products (hardware wallets, Hardware Security Modules, enclaves).

The current implementation runs on Intel SGX, available for Intel Core CPUs since generation 6 (SkyLake). Different trust models are available : by trusting Intel attestation mechanism and Ledger servers you can initialize the environment on an untrusted computer, or choose to only trust Intel isolation technology and initialize the environment on a temporarily trusted computer.

The target Trusted Computing Base is built from the following components : 

 * A [Moxie](http://moxielogic.org/) processor simulator for applications isolation
 * [Libsecp256k1](https://github.com/bitcoin-core/secp256k1) for secp256k1 based elliptic curve cryptography
 * [Micro ECC](https://github.com/kmackay/micro-ecc) for secp256r1 based elliptic curve cryptography
 * [libsodium](https://github.com/jedisct1/libsodium) for high level authenticated encryption primitives
 * [ctaes](https://github.com/bitcoin-core/ctaes) as constant time AES implementation

For a longer introduction, you can refer to our [Medium post](https://www.ledger.com/soft-launching-ledger-sgx-enclave/)

## Pre-requirements

 *  Linux x64 with the capability to add custom kernel modules or Windows environment with a SkyLake or above Intel Core CPU and compatible motherboard - most should be. For a cheap portable testing environment, the Acer Swift 3 can be a good choice.
 * Up to date BIOS and ME firmware v11.6 and higher recommanded


## Installing SGX runtime and SDK

The SGX runtime has to be installed on all environments to use the enclave. The SDK is also necessary to build the Python host package.

### Linux

Follow the instructions to build the [driver](https://github.com/01org/linux-sgx-driver)  and the [execution environment](https://github.com/01org/linux-sgx)

Make sure you install all requirements to use the Trusted Platform Service functions - a ME firmware upgrade might also be necessary.

### Windows

Follow the instructions to download the [SDK](https://software.intel.com/en-us/sgx) and associated software - a ME firmware upgrade might also be necessary

Then download and install [Microsoft Visual Studio 2017 Community](https://www.visualstudio.com/downloads/) and [Python 2.7 32 bits](https://www.python.org/downloads/windows/)

## Building the Python host package

The Python host package is the only thing you need to build if you plan to trust Ledger attestation and use the pre built enclave binaries provided in tee-releases

### Linux 

Make sure that the libffi-dev package is installed 

Run `python setup.py install` from host/py

### Windows

Make sure that the Visual C++ compiler for Python is **not** installed

Run `python setup.py install` from host/py

## Deterministic builds

Creating a deterministic build of the enclave let you verify that the distributed signed binary enclave matches the Open Source code - it is only necessary to build it if you want to rely on your own attestation scheme.

### Linux
  
 * Install Docker
 * Run `docker build -f Dockerfile-sgx-bootstrap` from tee/docker
 * Start a container in this image `docker run -i -t IMAGE ID /bin/bash` with the image id obtained from `docker images`
 * Copy the content of this repository to the container with `docker cp`
 * Run `prepare.sh` to download the dependencies from tee/
 * Run `make -f Makefile.sgx` from tee/   
 * The enclave can be found in `obj-sgx`

### Windows

The build process is slightly less automated and more complex on Windows - you'll need to use Visual Studio 2017 Community version 15.2(26430.12) and Intel SGX SDK version 1.8.100.38781

 * On a Linux host, download and prepare the dependencies by running `prepare.sh` in the tee/ directory
 * Open the `BolosSGX.sln` solution in tee/windows and rebuild the `Release` configuration of the solution
 * Remove the non deterministic elements with `python normalizePE.py ..\Release\BolosSGX.dll` (this require the pefile package to be installed previously)
 * The enclave can be found in `Release`

### Validating the build

To validate the build you can generate the enclave measurements to be signed and associate them with the signature provided in the tee-releases/ directory, running from the top directory

 * Create the enclave signing material with 

```
  sgx_sign gendata -enclave path_to_generated_library -config tee/Enclave/BolosSGX.config.xml -out enclave_hash.hex
```  
 * Compare enclave_hash.hex with the version stored in tee-releases/ for the given release
 * Merge the signature with 

```
  sgx_sign catsig -enclave path_to_generated_library -config tee/Enclave/BolosSGX.config.xml -out path_to_signed_library -key tee-releases/public.pem -sig path_to_signature_hex_in_tee_releases -unsigned enclave_hash.hex
```  

## Storing the enclave root of trust 

The enclave root of trust is a secp256k1 keypair generated by the enclave that can be used to [authenticate the running code](https://www.ledger.com/attestation-redux-proving-code-execution-on-the-ledger-platform/). You can choose to have this root of trust validated by Ledger and Intel servers or validate it yourself.

### Trusting Ledger server 

When trusting Ledger server, attestation keys can be provisioned remotely with the enclave quote validated by [Intel Attestation Service](https://software.intel.com/en-us/articles/intel-software-guard-extensions-remote-attestation-end-to-end-example)

You can perform the provisioning with the following command, from tee-release/ directory, using 1 or 2 for the key reference and a context output file you will reuse later - the integrity of the Operating System isn't critical.

On Linux :

```
python -m bolosenclave.endorsementSetupLedger --enclave linux/BolosSGX_signed.so --script scripts/endorsement_init.bin --key KEY_REFERENCE --output CONTEXT_OUTPUT.bin
```

On Windows :

```
python -m bolosenclave.endorsementSetupLedger --enclave windows/BolosSGX_signed.dll --script scripts/endorsement_init.bin --key KEY_REFERENCE --output CONTEXT_OUTPUT.bin
```

### Not trusting Ledger server

When not trusting Ledger server, the user retrieves the public key of the root of trust and provides a certificate. The integrity of the Operating System is critical - this step should be performed on a trusted configuration

On Linux :

```
python -m bolosenclave.endorsementSetup --enclave linux/BolosSGX_signed.so --script scripts/endorsement_init.bin --key KEY_REFERENCE --output CONTEXT_OUTPUT.bin
```

On Windows :

```
python -m bolosenclave.endorsementSetup --enclave windows/BolosSGX_signed.dll --script scripts/endorsement_init.bin --key KEY_REFERENCE --output CONTEXT_OUTPUT.bin
```

When prompted, collect the enclave public key and provide a certificate, which is just stored along the key materials without being validated - for example it can be a simple signature.

## Developing on BOLOS Enclave

Development for the enclave is done by cross compiling and signing C code cross compiled for the [Moxie architecture]((http://moxielogic.org/)) using [BOLOS SGX API](http://ledgerhq.github.io/bolos-enclave). Ledger provides CPU specific authorization tokens to run your code on the live enclave

### Installing Moxie cross compiler

The moxiebox cross compiler toolchain can be built from https://github.com/bloq/ora (contrib directory) or you can use a pre-built Docker image available at https://hub.docker.com/r/nbasim/moxiebox-bolos/

The Docker environment can be started as follows on Linux, creating a build environment on WORK_DIR

```
docker pull nbasim/moxiebox-bolos
mkdir WORK_DIR
cd WORK_DIR
echo "FROM nbasim/moxiebox-bolos" > Dockerfile
docker run -i -t moxiebox-bolos /bin/bash
export BOLOS_SGX_SDK=/home/ledger/bolos-sgx
```

Sample code is available in moxie/test

Code shall always be built on a trusted environment or at least validated / signed in a trusted environment before being run in production

### Obtaining an application token

By design and to protect against malicious code, the enclave only load code which is signed by Ledger - it is however possible to obtain a token to load your own applications on a single CPU.

You'll need to perform the following steps : 

 * Generate a secp256k1 keypair on a trusted computer - you can use 
```
python -m bolosenclave.generatePair
```

 * Obtain the Platform ID of the computer on which you're running the enclave with 

On Linux

```
python -m bolosenclave.getPlatformId --enclave linux/BolosSGX_signed.so 
```  

On Windows

```
python -m bolosenclave.getPlatformId --enclave windows/BolosSGX_signed.dll
```  
  * Provide the public key and the Platform ID on our developer slack (see Contact)

### Signing an application

You can sign an application directly with your private key on a trusted computer with 

```
python -m bolosenclave.signApp --elf application_to_sign --key private_key
```

Alternatively you can obtain a hash of the application and sign it using an alternative method with

```
python -m bolosenclave.hashApp --elf application_to_sign
```

### Running an application

Use the following command to run an application

On Linux

```
python -m bolosenclave.runApp --enclave linux/BolosSGX_signed.so  --elf application_to_run --signature signature --token token --context previous_context --parameters application_parametrs
```

On Windows

```
python -m bolosenclave.runApp --enclave windows/BolosSGX_signed.dll --elf application_to_run --signature signature --token token --context previous_context --parameters application_parametrs
```

Using those parameters : 

 * If the code is signed by Ledger, use the `--signature` option
 * If the code is signed by yourself, use the `--signature` and `--token` options, passing the signature your computed and your token
 * `--context` to provide a reference to a previous global enclave context, typically containing the attestation keys
 * `--parameters` to call the application with specific parameters

## Modifying the enclave

You're of course free to modify the enclave under the permissive Open Source Apache license and sign it yourself with a non whitelisted key.

An important caveat being that debugging cannot be disabled for non whitelisted keys - making the enclave secrets protection feature irrelevant.

You'll also need to change the enclave manifest in `tee/Enclave/BolosSGX.config.xml` to set the `<DisableDebug>` flag to 0

## FAQ

 * Can Intel steal my data ? 

Short answer : Not if a few non verifiable assumptions hold - note that's the common status of pretty much all commercial hardware available today, so it shouldn't be really surprising.

Long answer : you might want to get more familiar with the platform security and initial analysis - starting with a [general description from Intel](https://software.intel.com/en-us/articles/innovative-technology-for-cpu-based-attestation-and-sealing) and [initial analysis from Kudelski at Black Hat conference](https://www.blackhat.com/docs/us-16/materials/us-16-Aumasson-SGX-Secure-Enclaves-In-Practice-Security-And-Crypto-Review-wp.pdf), then consider the possible threats. Among those :

Is it possible to corrupt the random generator ? If that's the case, Intel could learn some information about the generated secrets

Are the wrapping keys bound to secret material that is known outside the CPU ? If that's the case, Intel could recover the wrapping keys and reveal all secrets directly 

Is it possible to issue a rogue microcode update without breaking the platform integrity ? If that's the case, Intel could recover the wrapping keys and reveal all secrets directly 

Is it possible to compromise Intel attestation service and validate arbitrary quotes ? If that's the case, Intel could break schemes relying on it (which is optional for this enclave)

 * Can Ledger steal my data ? 

Not if Intel implementation is correct : all secrets are bound to the enclave, not to the signer so compromising Ledger signing key would not reveal existing secrets.

If Ledger attestation service is compromised, consequences are similar to a compromise of Intel attestation service - schemes relying on the attestation could be broken

 * Can a third party steal my data ? 

Not if Intel implementation is correct and Ledger implementation is correct - that's where the source code review helps.

We're also offering an initial [Bitcoin bounty](https://github.com/ledgerhq/bolos-enclave-catchme) if you compromise the common secret data protection scheme - and more to come

 * How secure is the whole architecture ? 

Enclaves are mostly designed to protect the user against malware, when implemented properly, and this implementation is currently missing a Trusted Display, which makes the overall protection against smart malware that'd use the enclave as a signing oracle weaker. They also do not offer much protection against an attacker getting physical access to the hardware implementing enclave. If you wish to improve that, we design fine hardware wallets and HSM based solutions :)

 * What's Ledger attestation public key and certificate scheme ? 

Ledger attestation public key is 04502c2f1660ee9209247271a60f26dedc6b96f298aeda684855a9db1a0fc098fef0d48ac8e512df00b7511f75f9b56bcd52cf5510ccf744a5c113ae314e9f4742 on secp256k1

Ledger certificate is a signature of the SHA-256 hash of 0xFE || enclave uncompressed attestation public key

## Contact

Developers are welcome to our Developer Slack at http://slack.ledger.co in the #enclave channel

For other questions, specific customizations, supports or licensing custom code on multiple hosts please contact hello@ledger.fr

