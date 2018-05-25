FROM centos:7
MAINTAINER Hiep Huynh <hhuynh@firescope.com>

# Install dependencies
RUN yum -y install libpcap-devel jansson-devel openssl-devel
RUN mkdir -p /var/run/pmacct
RUN mkdir -p /firescope/system_config/pmacct/classifiers
COPY dependencies/resources/* /firescope/system_config/pmacct/
COPY dependencies/lib/* /usr/local/lib/
COPY src/*acctd /usr/local/sbin/
COPY src/classifiers/*.so /firescope/system_config/pmacct/classifiers/
