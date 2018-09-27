#include "fqdn_cache.h"
#include "uthash.h"

#define DEFAULT_FQDN_CACHE_PERCENT_REMOVAL 0.4

const u_int32_t SZ_IN_ADDR = sizeof(struct in_addr);
const u_int32_t SZ_IP_HOST_ENTRY = sizeof(struct ip_host_entry);
const u_int32_t SZ_SOCKADDR = sizeof(struct sockaddr);


time_t last_timestamp_ttl_checked = 0;
u_int32_t ttl_sample_counter = 0;
struct ip_host_entry *ip_host_cache = NULL;

void enforce_cache_size()
{
    if (HASH_COUNT(ip_host_cache) > config.fqdn_cache_size) {
      int entries_to_remove = config.fqdn_cache_size * DEFAULT_FQDN_CACHE_PERCENT_REMOVAL;
      if (config.debug) {
        Log(LOG_DEBUG, "DEBUG ( %s/core ): enforce_cache_size(): Pruning the Fully Qualified Domain Name cache to size[%d] of total[%d].\n", 
          config.name, config.fqdn_cache_size - entries_to_remove, config.fqdn_cache_size);
      }
      struct ip_host_entry *entry, *tmp_entry;
      HASH_ITER(hh, ip_host_cache, entry, tmp_entry) {
        if (entries_to_remove > 0) {
          if (config.debug) {
            char ip[INET6_ADDRSTRLEN];
            addr_to_str(ip, &entry->ip_address);
            Log(LOG_DEBUG, "DEBUG ( %s/core ): enforce_cache_size(): Removing %s[%s] from cache.\n", config.name, ip, entry->host);
          }

          /* Prune the first entry (loop is based on insertion order so this deletes the oldest item) */
          HASH_DELETE(hh, ip_host_cache, entry);
          free(entry);
          entries_to_remove--;
        } else {
          break;
        }
      }
    }
}

struct ip_host_entry *add_to_cache(struct in_addr *key, char *value)
{
    struct ip_host_entry *entry = malloc(SZ_IP_HOST_ENTRY);
    memcpy(&entry->ip_address, key, SZ_IN_ADDR);
    strlcpy(entry->host, value, FQDN_MAXHOST);
    HASH_ADD(hh, ip_host_cache, ip_address, SZ_IN_ADDR, entry);
    enforce_cache_size();
    return entry;
}



/* LRU implementation of cache */
struct ip_host_entry *lookup_cache(struct in_addr *key)
{
	struct ip_host_entry *entry;

        HASH_FIND(hh, ip_host_cache, key, SZ_IN_ADDR, entry);
	if (entry) {
/*
          if (config.debug) {
            char ip[INET6_ADDRSTRLEN];
            addr_to_str(ip, &entry->ip_address);
            Log(LOG_DEBUG, "DEBUG ( %s/core ): lookup_cache(): Found fqdn[%s] for ip address[%s].\n", config.name, entry->host, ip);
          }
*/

          /* Remove then re-add entry so it will be pushed to the front of the list leaving the LRU (Least Recently Used) 
             at the back for removal when the cache size has been exceeded. */
          HASH_DELETE(hh, ip_host_cache, entry);
          HASH_ADD(hh, ip_host_cache, ip_address, SZ_IN_ADDR, entry);
          return entry;
	}
	return NULL;
}

void enforce_cache_ttl()
{
  if (ttl_sample_counter > config.fqdn_cache_ttl_nth_sample)
  {
    ttl_sample_counter = 0;
    time_t now = time(NULL);
    if (config.debug) {
      Log(LOG_DEBUG, "DEBUG ( %s/core ): enforce_cache_ttl(): Determining if the Fully Qualified Domain Name cache has exceeded TTL[%ds]: now[%d] - last_cleared[%d] = %d\n", 
        config.name, config.fqdn_cache_ttl, now, last_timestamp_ttl_checked, now - last_timestamp_ttl_checked);
    }

    if (now - last_timestamp_ttl_checked >= config.fqdn_cache_ttl) {
      if (config.debug) {
        Log(LOG_DEBUG, "DEBUG ( %s/core ): enforce_cache_ttl(): Clearing the Fully Qualified Domain Name cache.\n", config.name);
      }

      struct ip_host_entry *entry, *tmp_entry;
      HASH_ITER(hh, ip_host_cache, entry, tmp_entry) {
        HASH_DELETE(hh, ip_host_cache, entry);
        free(entry);
      }
      last_timestamp_ttl_checked = now;
    } 
  } else {
    ttl_sample_counter++;
  }
}

int lookup_fqdn(struct in_addr *ip_address, char *host)
{
    struct sockaddr_in sa;
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = ip_address->s_addr;
    struct timeval t0;
    struct timeval t1;

    gettimeofday(&t0, 0);

    int res = getnameinfo((struct sockaddr*)&sa, SZ_SOCKADDR, host, FQDN_MAXHOST, 0, 0, NI_NAMEREQD);
    /*
    struct hostent *he;
    he = gethostbyaddr(ip_address, sizeof(ip_address), AF_INET);
    if (he) {
      strncpy(host, he->h_name, FQDN_MAXHOST);
      res = 0;
    } else {
      res = h_errno;
    }
    */

    gettimeofday(&t1, 0);
    if (config.debug) {
     char ip[INET6_ADDRSTRLEN];
     inet_ntop(AF_INET, ip_address, ip, INET6_ADDRSTRLEN);
     float elapsed = (t1.tv_sec - t0.tv_sec) * 1000.0f + (t1.tv_usec - t0.tv_usec) / 1000.0f;
     Log(LOG_DEBUG, "DEBUG ( %s/core ): lookup_fqdn(): ip[%s] dns[%s] time taken[%fms] status[%d].\n", config.name, ip, res ? gai_strerror(res) : host, elapsed, res);
    }
    return res;
}

char *reverse_lookup_ia(struct in_addr *ip_address) {
  enforce_cache_ttl();

  struct ip_host_entry *entry = lookup_cache(ip_address);
  if (entry) {
    return entry->host;
  } else {
    char host[FQDN_MAXHOST];
    int res = lookup_fqdn(ip_address, host);
    if (res == 0) {
      entry = add_to_cache(ip_address, host);
    } else  {
      entry = add_to_cache(ip_address, "");
    }

    if (entry) {
      return entry->host;
    }
  }
  return NULL;
}

char *reverse_lookup_ha(struct host_addr *ip_address) {
  return reverse_lookup_ia(&ip_address->address.ipv4);
}
