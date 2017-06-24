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

import sys
import pefile
pe = pefile.PE(sys.argv[1], fast_load=True);
pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'],  pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DEBUG'] ])

f = open(sys.argv[1], "r+")

f.seek(pe.FILE_HEADER.get_field_absolute_offset('TimeDateStamp'))
f.write("\0" * 4)
f.seek(pe.OPTIONAL_HEADER.get_field_absolute_offset('CheckSum'))
f.write("\0" * 4)
f.seek(pe.DIRECTORY_ENTRY_EXPORT.struct.get_field_absolute_offset('TimeDateStamp'))
f.write("\0" * 4)
for debug in pe.DIRECTORY_ENTRY_DEBUG:
        f.seek(debug.struct.get_field_absolute_offset('TimeDateStamp'))
        f.write("\0" * 4)
        if debug.entry != None:
                f.seek(debug.entry.get_file_offset())
                f.write("\0" * debug.struct.SizeOfData)
f.close()

