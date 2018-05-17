CC = gcc
CFLAGS = -shared -fPIC
LIBS = -ldl
CHECKS = check_endianess
CLASSIFIERS = flow_url

all: $(CHECKS) $(CLASSIFIERS)

check_endianess: 
	$(CC) -o check_endianess check_endianess.c

rtp: rtp.c
	DEFS=`./check_endianess`; \
	$(CC) $(CFLAGS) `echo $$DEFS` -o $@.so $? $(LIBS) 

edonkey: edonkey.c
	DEFS=`./check_endianess`; \
	$(CC) $(CFLAGS) `echo $$DEFS` -o $@.so $? $(LIBS) 

flow_url: flow_url.c 
	DEFS=`./check_endianess`; \
	$(CC) $(CFLAGS) `echo $$DEFS` -o $@.so $? $(LIBS) 

clean:
	rm -f check_endianess *.o *.so

install: all
	cp $(CLASSIFIERS).so /firescope/system_config/pmacct/classifiers
