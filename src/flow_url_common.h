
#ifndef __FLOW_URL_COMMON_H_
#define __FLOW_URL_COMMON_H_

#include "classifiers/flow_url.h"
#include "uthash.h"
#include "utlist.h"

#define SHM_TABLE_NAME "/firescope/system_config/pmacct"

typedef struct flow_url_client {
    char ip_text[INET6_ADDRSTRLEN];
    struct flow_url_client *next;
} flow_url_client;

struct flow_url_entry {
  struct flow_url_key key;
  char ip_text[INET6_ADDRSTRLEN];
  char hostname[FQDN_MAXHOST];
  flow_url_client *clients;
  char method[HTTP_METHOD_LEN];
  u_int16_t invocations;
  time_t ts;
  UT_hash_handle hh;
};

static const u_int32_t SZ_FLOW_URL_CLIENT = sizeof(struct flow_url_client);
static const u_int32_t SZ_FLOW_URL_ENTRY = sizeof(struct flow_url_entry);

extern void init_url_reader();
extern void init_url_entries();
extern void process_url();
extern void url_entries_purge();

#endif  /* __FLOW_URL_COMMON_H_ */
