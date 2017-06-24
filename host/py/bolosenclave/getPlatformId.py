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

args = parser.parse_args()

if args.enclave == None:
        raise Exception("No enclave specified")

link = BolosEnclaveLink(args.enclave, args.debugEnclave, args.debug)
link.create_persistent_context()
app = BolosEnclave(link)
response = app.getId()

print "Platform ID " + str(response).encode('hex')

link.close()
