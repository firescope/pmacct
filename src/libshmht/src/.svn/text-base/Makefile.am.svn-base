## Process this file with automake to produce Makefile.in

lib_LTLIBRARIES = libshmht_@SHMHT_API_VERSION@.la

libshmht_@SHMHT_API_VERSION@_la_CFLAGS = -Werror 			\
	-I$(top_srcdir)/include

libshmht_@SHMHT_API_VERSION@_la_SOURCES = shmht.c

TESTS=run_tests
check_PROGRAMS = run_tests
run_tests_SOURCES = shmht.c shmht_tests.c 
run_tests_CFLAGS=$(AM_CFLAGS) $(libshmht_@SHMHT_API_VERSION@_la_CFLAGS) 
run_tests_LDADD=$(AM_LDADD) -lcgreen -lm
run_tests.c: $(libshmht_@SHMHT_API_VERSION@_la_SOURCES)
	$(TESTGEN) $(TESTGEN_OPTS) shmht_tests.c > $@


