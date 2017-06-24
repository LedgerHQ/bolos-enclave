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
parser.add_argument("--script", help="Endorsement script to use")
parser.add_argument("--key", help="Reference of the endorsement key to setup (1 or 2)", type=auto_int)        
parser.add_argument("--output", help="Output file to store the persistent context to")

args = parser.parse_args()

if args.enclave == None:
        raise Exception("No enclave specified")
if args.script == None:
        raise Exception("No endorsement script specified")
if args.key != 1 and args.key != 2:
        raise Exception("Invalid endorsement key reference")
if args.output == None:
        raise Exception("No output specified")

link = BolosEnclaveLink(args.enclave, args.debugEnclave, args.debug)
ctx = link.create_persistent_context()
if args.debug:
        print "initialized context " + str(ctx).encode('hex')
app = BolosEnclave(link)
app.openSession()

f = open(args.script, "rb")
endorsementInit = app.loadElf(f, chr(args.key - 1) + chr(0), maxResponseSize=200000)

print "To endorse " + str(endorsementInit['response']).encode('hex')

certificate = raw_input("Enter hex encoded certificate : ")
certificate = certificate.decode('hex')

f = open(args.script, "rb")
app.loadElf(f, chr(args.key - 1) + chr(len(certificate)) + certificate, maxResponseSize=200000)

ctx = link.get_persistent_context()
if args.debug:
        print "personalized context " + str(ctx).encode('hex')
f = open(args.output, "wb")
f.write(ctx)
f.close()

app.closeSession()
link.close()
