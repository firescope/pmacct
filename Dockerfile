FROM centos:7
MAINTAINER Hiep Huynh <hhuynh@firescope.com>

# Install dependencies
RUN yum -y install \
    gcc libpcap-devel \
    jansson-devel openssl-devel \
    git libtool make cmake tcpdump \
    && yum clean all
RUN mkdir -p /firescope/system_config/pmacct/classifiers
COPY pmacct/* /firescope/system_config/pmacct
COPY include/* /usr/local/include/
COPY lib/* /usr/local/lib/

ENV RABBITMQ_LIBS -L/usr/local/lib -lrabbitmq
ENV RABBITMQ_CFLAGS -I/usr/local/include
RUN cd /tmp && git clone -b pmacct-firescope https://github.com/firescope/pmacct.git \
    && cd pmacct \
    && ./autogen.sh \
    && ./configure --enable-rabbitmq --enable-jansson \
    && make -j4 \
    && make install
RUN cd /tmp/pmacct/src/classifiers \
    && gcc -o check_endianess check_endianess.c \
    && gcc -shared -fPIC `./check_endianess` -o flow_url.so flow_url.c -ldl \
    && cp ./flow_url.so /firescope/system_config/pmacct/classifiers
