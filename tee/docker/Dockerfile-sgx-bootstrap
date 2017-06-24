FROM ubuntu:16.04
MAINTAINER Nicolas Bacca <nicolas@ledger.fr>

RUN apt-get -qq update
RUN apt-get -qq install -y build-essential automake autoconf libtool 
RUN apt-get -qq install -y cmake libjsoncpp-dev libjsonrpccpp-dev libjsonrpccpp-tools libsqlite3-0 libsqlite3-dev libboost-all-dev libmicrohttpd-dev libcurl4-openssl-dev odb
RUN apt-get -qq install -y wget
RUN apt-get -qq install -y git

RUN useradd -ms /bin/bash sgx 
RUN chown -R sgx:sgx /opt/

