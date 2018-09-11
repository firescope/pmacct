[![Build Status](https://travis-ci.org/pmacct/pmacct.svg?branch=master)](https://travis-ci.org/pmacct/pmacct)

DOCUMENTATION
=============

Custom FireScope functionality which adds SSL support, fqdn, and flow collapsing capabilities.

- Online:
  * GitHub Wiki Pages: https://github.com/pmacct/pmacct/wiki
  * GitHub master code: https://github.com/pmacct/pmacct/

- Distribution tarball:
  * ChangeLog: History of features version by version 
  * CONFIG-KEYS: Available configuration directives explained
  * QUICKSTART: Examples, command-lines, quickstart guides
  * FAQS: FAQ document
  * INSTALL: basic installation guide
  * docs/: Miscellaneous internals, UNIX signals, SQL triggers documents 
  * examples/: Sample configs, maps, AMQP/Kafka consumers, clients 
  * sql/: SQL documentation, default SQL schemas and customization tips

# BUILDING

- Build GitHub code:
  * git clone https://github.com/pmacct/pmacct.git
  * cd pmacct
  * ./autogen.sh *[pkg-config, libtool, autoconf, automake and bash packages required]*
  * ./configure *[check-out available configure knobs via ./configure --help]* 
  * make
  * make install *[with super-user permission]*

Docker

- Build release and push to registry
  * docker login registry.gitlab.com
  * docker build -t push registry.gitlab.com/firescope/stratis/pmacct/edge-pmacct .
  * docker tag <IMAGE ID> registry.gitlab.com/firescope/stratis/pmacct/edge-pmacct:4.0.0-alpha
  * docker tag <IMAGE ID> registry.gitlab.com/firescope/stratis/pmacct/edge-pmacct:4.0.0-beta1
  * docker tag <IMAGE ID> registry.gitlab.com/firescope/stratis/pmacct/edge-pmacct:latest
  * docker push registry.gitlab.com/firescope/stratis/pmacct/edge-pmacct
