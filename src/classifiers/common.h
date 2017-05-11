/* includes */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include "common-dep.h"

/* definitions */
#define MAX_PROTOCOL_LEN 16
typedef u_int32_t pm_class_t;

/* structures */
struct pkt_classifier_data {
  struct timeval stamp;
  char *packet_ptr;
  char *l3_ptr;
  char *l4_ptr;
  char *payload_ptr;
  u_int16_t l3_proto;
  u_int16_t l4_proto;
  u_int16_t plen;
  u_int8_t tentatives;
  u_int16_t sampling_rate;
};

struct pkt_classifier {
  pm_class_t id;
  char protocol[MAX_PROTOCOL_LEN];
  regexp *pattern;
  pm_class_t (*func)(struct pkt_classifier_data *, int, void **, void **, void **);
  conntrack_helper ct_helper;
  void *extra;
};

/* a few "library" functions provided by the collector; being able
   to use them requires the executable to export such symbols to the
   dlopen()ed classifier */
extern pm_class_t pmct_register(struct pkt_classifier *);
extern void pmct_unregister(pm_class_t);
extern pm_class_t pmct_find_first_free();
extern pm_class_t pmct_find_last_free();
extern int pmct_isfree(pm_class_t);
extern int pmct_get(pm_class_t, struct pkt_classifier *);
extern int pmct_get_num_entries();
