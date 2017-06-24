"""
*******************************************************************************
*   BOLOS Enclave
*   (c) 2017 Ledger
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************
"""

import argparse
from .bolosEnclaveLink import BolosEnclaveLink
from .bolosEnclave import BolosEnclave

def auto_int(x):
    return int(x, 0)

parser = argparse.ArgumentParser()
parser.add_argument("--debug", help="Display debug information", action='store_true')
parser.add_argument("--debugEnclave", help="Run enclave in debug mode", action='store_true')
parser.add_argument("--enclave", help="Enclave to use")
parser.add_argument("--elf", help="ELF file to run")
parser.add_argument("--signature", help="Optional ELF signature if not present in .ledger section (hex encoded)")
parser.add_argument("--token", help="Optional token for this TCB if running custom code (hex encoded)")
parser.add_argument("--context", help="Optional persistent context to use (or create a new one)")
parser.add_argument("--parameters", help="Optional parameters to pass to the application (hex encoded)")
parser.add_argument("--maxResponseSize", help="Optional maximum response size (default 4096)", type=auto_int)

args = parser.parse_args()

maxResponseSize = 4096
parameters = None
signature = None
token_id = None
token_key = None
token_signature = None

if args.enclave == None:
        raise Exception("No enclave specified")
if args.elf == None:
        raise Exception("No ELF file specified")
if args.parameters != None:
        parameters = args.parameters.decode('hex')
if args.maxResponseSize != None:
        maxResponseSize = args.maxResponseSize
if args.signature != None:
        signature = args.signature.decode('hex')
if args.token != None:
        token = bytearray(args.token.decode('hex'))
        token_key = str(token[0:65])
        signatureLength = token[66] + 2
        token_signature = str(token[65 : 65 + signatureLength])
        token_id = str(token[65 + signatureLength:])


link = BolosEnclaveLink(args.enclave, args.debugEnclave, args.debug)
if args.context == None:
        ctx = link.create_persistent_context()
        if args.debug:
                print "initialized context " + str(ctx).encode('hex')
else:
        f = open(args.context, "rb")
        ctx = f.read()
        f.close()
        link.set_persistent_context(ctx) 

app = BolosEnclave(link)
app.openSession()

if args.token != None:
    app.provideToken(token_id, token_key, token_signature)

f = open(args.elf, "rb")
response = app.loadElf(f, parameters, maxResponseSize=maxResponseSize, signature=signature)
f.close()

print "Response " + str(response['response']).encode('hex')

app.closeSession()
link.close()
