#!/bin/sh
set -ex
yum -y install libpcap-devel jansson-devel openssl-devel git gcc libtool make cmake
cp -pfr dependencies/lib/* /usr/local/lib
cp -pfr dependencies/include/* /usr/local/include
export RABBITMQ_LIBS="-L/usr/local/lib -lrabbitmq"
export RABBITMQ_CFLAGS=-I/usr/local/include
./autogen.sh
./configure --enable-rabbitmq --enable-jansson
make -j4
make install

# Build url sniffer
mkdir -p /firescope/system_config/pmacct/classifiers 
cd src/classifiers
make install
