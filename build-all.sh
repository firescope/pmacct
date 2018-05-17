#!/bin/sh
yum -y install libpcap-devel jansson-devel openssl-devel git gcc libtool make cmake tcpdump
cp -pfr dependencies/lib/* /usr/local/lib
cp -pfr dependencies/include/* /usr/local/include
export RABBITMQ_LIBS="-L/usr/local/lib -lrabbitmq"
export RABBITMQ_CFLAGS=-I/usr/local/include
./autogen.sh
./configure --enable-rabbitmq --enable-jansson
make -j4
make install
cd src/classifiers
#gcc -o check_endianess check_endianess.c
#gcc -shared -fPIC `./check_endianess` -o flow_url.so flow_url.c -ldl
make install
#cp ./flow_url.so /firescope/system_config/pmacct/classifiers
