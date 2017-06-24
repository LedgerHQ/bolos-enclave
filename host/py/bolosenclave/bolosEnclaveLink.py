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

from _libbolosenclave import ffi,lib

class BolosEnclaveLink(object):

	def __init__(self, enclavePath, debug=False, debugApp=False):
		enclaveId = ffi.new("bolos_enclave_id_t*")
		status = lib.bolos_enclave_open(enclavePath, debug, enclaveId) 
		if status != lib.BOLOS_ENCLAVE_STATUS_OK:
			raise Exception("Failed to open enclave %d" % status)
		self.enclaveId = enclaveId[0]
		self.raId = None
		self.debugApp = debugApp

	def get_extended_epid_group_id(self):
		groupId = ffi.new("uint32_t*")
		status = lib.bolos_enclave_get_extended_epid_group_id(groupId)
		if status != lib.BOLOS_ENCLAVE_STATUS_OK:
			raise Exception("Failed to get extended EPID group ID %d" % status)
		return groupId[0]

	def create_persistent_context(self, maxSize=4096):
		if self.enclaveId == None:
			raise Exception("Enclave is not open")		
		context = ffi.new("uint8_t[%d]" % maxSize)
		contextSize = ffi.new("uint32_t*")
		contextSize[0] = maxSize
		status = lib.bolos_enclave_create_persistent_context(self.enclaveId, context, contextSize)
		if status != lib.BOLOS_ENCLAVE_STATUS_OK:
			raise Exception("Failed to set persistent context %d" % status)		
		return bytearray(ffi.buffer(context, contextSize[0]))

	def get_persistent_context(self, maxSize=4096):
		if self.enclaveId == None:
			raise Exception("Enclave is not open")		
		context = ffi.new("uint8_t[%d]" % maxSize)
		contextSize = ffi.new("uint32_t*")
		contextSize[0] = maxSize
		status = lib.bolos_enclave_get_persistent_context(self.enclaveId, context, contextSize)
		if status != lib.BOLOS_ENCLAVE_STATUS_OK:
			raise Exception("Failed to get persistent context %d" % status)		
		return bytearray(ffi.buffer(context, contextSize[0]))


	def set_persistent_context(self, context):
		if self.enclaveId == None:
			raise Exception("Enclave is not open")		
		status = lib.bolos_enclave_set_persistent_context(self.enclaveId, context, len(context))
		if status != lib.BOLOS_ENCLAVE_STATUS_OK:
			raise Exception("Failed to set persistent context %d" % status)		

	def is_persistent_context_dirty(self):
		if self.enclaveId == None:
			raise Exception("Enclave is not open")		
		dirtyFlag = ffi.new("bool*")
		status = lib.bolos_enclave_is_persistent_context_dirty(self.enclaveId, dirtyFlag)
		if status != lib.BOLOS_ENCLAVE_STATUS_OK:
			raise Exception("Failed to get persistent context dirty flag %d" % status)		
		return dirtyFlag[0] != 0

	def clear_persistent_context_dirty(self):
		if self.enclaveId == None:
			raise Exception("Enclave is not open")		
		status = lib.bolos_enclave_clear_persistent_context_dirty_flag(self.enclaveId)		
		if status != lib.BOLOS_ENCLAVE_STATUS_OK:
			raise Exception("Failed to clear persistent context dirty flag %d" % status)		

	def ra_init(self, openPSESession=True):
		if self.enclaveId == None:
			raise Exception("Enclave is not open")		
		if self.raId != None:
			self.ra_close()
		raId = ffi.new("bolos_ra_context_t*")
		msg1 = ffi.new("uint8_t[%d]" % lib.BOLOS_ENCLAVE_MSG1_SIZE)
		msg1Size = ffi.new("uint32_t*")
		msg1Size[0] = lib.BOLOS_ENCLAVE_MSG1_SIZE
		status = lib.bolos_enclave_ra_init(self.enclaveId, openPSESession, msg1, msg1Size, raId)
		if status != lib.BOLOS_ENCLAVE_STATUS_OK:
			raise Exception("Failed to initialize RA session %d" % status)		
		self.raId = raId[0]
		return bytearray(ffi.buffer(msg1, msg1Size[0]))


	def ra_close(self):
		if self.enclaveId == None:
			raise Exception("Enclave is not open")
		if self.raId == None:
			raise Exception("RA session is not open")		
		lib.bolos_enclave_ra_close(self.enclaveId, self.raId)
		self.raId = None

	def ra_handshake(self, msg2, maxMsg3Size=4096):
		if self.enclaveId == None:
			raise Exception("Enclave is not open")
		if self.raId == None:
			raise Exception("RA session is not open")		
		msg3 = ffi.new("uint8_t[%d]" % maxMsg3Size)		
		msg3Size = ffi.new("uint32_t*")
		msg3Size[0] = maxMsg3Size
		status = lib.bolos_enclave_ra_handshake(self.enclaveId, self.raId, msg2, len(msg2), msg3, msg3Size)
		if status != lib.BOLOS_ENCLAVE_STATUS_OK:
			raise Exception("Failed to perform RA handshake %d" % status)		
		return bytearray(ffi.buffer(msg3, msg3Size[0]))

	def ra_get_attestation_key(self, keyIndex, maxAttestationSize=1024):
		if self.enclaveId == None:
			raise Exception("Enclave is not open")
		if self.raId == None:
			raise Exception("RA session is not open")		
		if keyIndex != lib.BOLOS_ATTESTATION_KEY_1 and keyIndex != lib.BOLOS_ATTESTATION_KEY_2:
			raise Exception("Invalid key index")
		attestation = ffi.new("uint8_t[%d]" % maxAttestationSize)
		attestationSize = ffi.new("uint32_t*")
		attestationSize[0] = maxAttestationSize
		status = lib.bolos_enclave_ra_get_attestation_key(self.enclaveId, self.raId, keyIndex, attestation, attestationSize)
		if status != lib.BOLOS_ENCLAVE_STATUS_OK:
			raise Exception("Failed to get key attestation %d" % status)		
		return bytearray(ffi.buffer(attestation, attestationSize[0]))

	def ra_set_personalization_key(self, keyBlob):
		if self.enclaveId == None:
			raise Exception("Enclave is not open")
		if self.raId == None:
			raise Exception("RA session is not open")		
		status = lib.bolos_enclave_ra_set_personalization_key(self.enclaveId, self.raId, keyBlob, len(keyBlob))		
		if status != lib.BOLOS_ENCLAVE_STATUS_OK:
			raise Exception("Failed to set personalization key %d" % status)		

	def exchange(self, command, maxResponseSize=4096):
		if self.enclaveId == None:
			raise Exception("Enclave is not open")
		response = ffi.new("uint8_t[%d]" % maxResponseSize)		
		responseSize = ffi.new("uint32_t*")
		responseSize[0] = maxResponseSize
		if self.debugApp:
			print "> " + str(command).encode('hex')
		status = lib.bolos_enclave_exchange(self.enclaveId, command, len(command), response, responseSize)
		if status != lib.BOLOS_ENCLAVE_STATUS_OK:
			raise Exception("Failed to exchange command %d" % status)		
		response = bytearray(ffi.buffer(response, responseSize[0]))
		if self.debugApp:
			print "< " + str(response).encode('hex')
		return response		

	def close(self):
		if self.enclaveId == None:
			raise Exception("Enclave is not open")
		lib.bolos_enclave_close(self.enclaveId)
		self.enclaveId = None

