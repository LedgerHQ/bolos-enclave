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

import struct
from .bolosEnclaveLink import BolosEnclaveLink
from elftools.elf.elffile import ELFFile
from elftools.elf.constants import P_FLAGS

class BolosEnclave(object):

	CMD_SESSION_OPEN = 0x0001
	CMD_SESSION_CLOSE = 0x0002
	CMD_GET_PLATFORM_ID = 0x0003
	CMD_PROVIDE_TOKEN = 0x0004
	CMD_GET_VERSION = 0x0005

	CMD_CODE_INIT = 0x0101
	CMD_CODE_LOAD_SECTION = 0x0102
	CMD_CODE_RUN = 0x0103
	CMD_CODE_RESUME = 0x0104

	MSG_LOAD_SECTION_FLAG_READ_ONLY = 0x01

	STATUS_CODE_EXEC_OK = 0x01
	STATUS_CODE_EXEC_LOG = 0x02
	STATUS_CODE_EXEC_SUSPENDED = 0x03
	STATUS_CODE_EXEC_ERROR = 0x80		

	def __init__(self, link):
		self.link = link

	def getId(self):
		cmd = struct.pack(">H", self.CMD_GET_PLATFORM_ID)
		response = self.link.exchange(cmd)
		if response[0] != self.STATUS_CODE_EXEC_OK:
			raise Exception("Unexpected status on GET_PLATFORM_ID %.2x" % response[0])
		return response[1:]

	def provideToken(self, id, key, token):	
		if len(key) != 65:
			raise Exception("Invalid key")
		cmd = struct.pack(">H", self.CMD_PROVIDE_TOKEN)
		cmd = cmd + str(key)
		cmd = cmd + struct.pack(">I", len(id))
		cmd = cmd + struct.pack(">I", len(token))
		cmd = cmd + id
		cmd = cmd + token
		response = self.link.exchange(cmd)
		if response[0] != self.STATUS_CODE_EXEC_OK:
			raise Exception("Unexpected status on PROVIDE_TOKEN %.2x" % response[0])

	def openSession(self, executionSlots=1, timeout=0):
		cmd = struct.pack(">H", self.CMD_SESSION_OPEN)
		cmd = cmd + struct.pack(">I", executionSlots)
		cmd = cmd + struct.pack(">I", timeout)
		response = self.link.exchange(cmd)
		if response[0] != self.STATUS_CODE_EXEC_OK:
			raise Exception("Unexpected status on SESSION_OPEN %.2x" % response[0])

	def closeSession(self):
		cmd = struct.pack(">H", self.CMD_SESSION_CLOSE)
		response = self.link.exchange(cmd)
		if response[0] != self.STATUS_CODE_EXEC_OK:
			raise Exception("Unexpected status on SESSION_CLOSE %.2x" % response[0])

	def loadElf(self, elfStream, parameters="", stackSize=100000, maxResponseSize=4096, continuation=None, signature=None):		
		if parameters == None:
			parameters = ""
		elffile = ELFFile(elfStream)
		# Locate signature if not passed
		if signature == None:
			for section in elffile.iter_sections():
				if section.name == '.ledger':
					signature = section.data()[0:ord(section.data()[1]) + 2]
					break
		if signature == None:
			raise Exception("Missing code signature")
		# Allocate session
		allocateSize = stackSize
		for segment in elffile.iter_segments():
			if segment['p_type'] == 'PT_LOAD':
				allocateSize = allocateSize + segment['p_memsz']
		cmd = struct.pack(">H", self.CMD_CODE_INIT)
		cmd = cmd + struct.pack(">I", allocateSize)
		response = self.link.exchange(cmd)
		if response[0] != self.STATUS_CODE_EXEC_OK:
			raise Exception("Unexpected status on CODE_INIT %.2x" % response[0])
		# Load each component
		for segment in elffile.iter_segments():
			if segment['p_type'] == 'PT_LOAD':
				flags = 0
				if ((segment['p_flags'] & P_FLAGS.PF_W) == 0):
					flags = flags | self.MSG_LOAD_SECTION_FLAG_READ_ONLY
				cmd = struct.pack(">H", self.CMD_CODE_LOAD_SECTION)
				cmd = cmd + chr(flags)
				cmd = cmd + struct.pack(">I", segment['p_vaddr'])
				cmd = cmd + struct.pack(">I", segment['p_vaddr'] + segment['p_memsz'])
				cmd = cmd + struct.pack(">I", segment['p_filesz'])
				cmd = cmd + segment.data()
				response = self.link.exchange(cmd)
				if response[0] != self.STATUS_CODE_EXEC_OK:
					raise Exception("Unexpected status on CODE_LOAD_SECTION %.2x" % response[0])
		# Run or resume
		if continuation == None:
			cmd = struct.pack(">H", self.CMD_CODE_RUN)
			cmd = cmd + struct.pack(">I", elffile.header['e_entry'])
			cmd = cmd + struct.pack(">I", stackSize)
			cmd = cmd + struct.pack(">I", 0)
			cmd = cmd + struct.pack(">I", len(parameters))
			cmd = cmd + struct.pack(">I", len(signature))
			cmd = cmd + str(parameters)
			cmd = cmd + signature		
		else:
			cmd = struct.pack(">H", self.CMD_CODE_RESUME)
			cmd = cmd + struct.pack(">I", continuation['slot'])
			cmd = cmd + struct.pack(">I", len(continuation['blob']))
			cmd = cmd + struct.pack(">I", 0)
			cmd = cmd + struct.pack(">I", len(parameters))
			cmd = cmd + str(continuation['blob'])
			cmd = cmd + str(parameters)
		response = self.link.exchange(cmd, maxResponseSize)
		result = {}
		if response[0] == self.STATUS_CODE_EXEC_OK:						
			result['suspended'] = False
			result['response'] = response[1:]
		elif response[0] == self.STATUS_CODE_EXEC_SUSPENDED:
			result['suspended'] = True
			slot, blobSize, appDataSize = struct.unpack(">III", str(response[1 : 1 + 12]))
			result['slot'] = slot
			result['blob'] = response[1 + 12 : 1 + 12 + blobSize]
			result['response'] = response[1 + 12 + blobSize : 1 + 12 + blobSize + appDataSize]
		else:
			raise Exception("Application error reported %.2x" % response[0])
		return result
