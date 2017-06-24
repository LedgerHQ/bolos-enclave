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

from setuptools import setup, find_packages
from os.path import dirname, join

here = dirname(__file__)
setup(
    name='bolosenclave',
    version='0.1.0',
    author='BTChip',
    author_email='hello@ledger.fr',
    description='Python library to communicate with Ledger BOLOS SGX Enclave',
    #long_description=open(join(here, 'README.md')).read(),
    url='https://github.com/LedgerHQ/bolos-enclave',
    packages=find_packages(exclude=('_cffi_build', '_cffi_build.*')),
    setup_requires=['cffi>=1.3.0'],
    install_requires=['cffi>=1.3.0', 'pyelftools>=0.24', 'protobuf>=2.6.1', 'ecpy>=0.8.1'],
    include_package_data=True,
    zip_safe=False,
    cffi_modules=["_cffi_build/build.py:ffibuilder"],
    classifiers=[
	'License :: OSI Approved :: Apache Software License',
        'Operating System :: POSIX :: Linux',
        'Operating System :: Microsoft :: Windows',
	'Operating System :: MacOS :: MacOS X'
    ]
)

