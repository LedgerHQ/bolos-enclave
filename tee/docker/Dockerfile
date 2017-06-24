FROM nbasim/sgx-bootstrap 
MAINTAINER Nicolas Bacca <nicolas@ledger.fr>

USER sgx
WORKDIR /home/sgx
RUN mkdir sgx
RUN wget -O sgx/sgx_linux_ubuntu16.04.1_x64_sdk_1.8.100.37689.bin https://download.01.org/intel-sgx/linux-1.8/sgx_linux_ubuntu16.04.1_x64_sdk_1.8.100.37689.bin
RUN chmod a+x sgx/sgx_linux_ubuntu16.04.1_x64_sdk_1.8.100.37689.bin
RUN echo -e 'no\n/opt/intel' | $PWD/sgx/sgx_linux_ubuntu16.04.1_x64_sdk_1.8.100.37689.bin
RUN echo 'source /opt/intel/sgxsdk/environment' >> $PWD/.bashrc

