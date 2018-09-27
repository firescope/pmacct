
#ifndef _FQDN_CACHE_H_
#define _FQDN_CACHE_H_

#include "pmacct.h"
#include "network.h"
#include "uthash.h"

struct ip_host_entry {
    struct in_addr ip_address; /* key */
    char host[FQDN_MAXHOST];
    UT_hash_handle hh;         /* makes this structure hashable */
};

extern char *reverse_lookup_ha(struct host_addr *ip_address);
extern char *reverse_lookup_ia(struct in_addr *ip_address);

#endif /* _FQDN_CACHE_H_ */

