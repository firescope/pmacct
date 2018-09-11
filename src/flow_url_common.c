#include <jansson.h>
#include "pmacct-defines.h"
#include "network.h"
#include "amqp_common.h"
#include "fqdn_cache.h"
#include "shmht.h"
#include "flow_url_common.h"
#include "flow_collapse.h"

#define MODULE_NAME "flow_url_common"
#define EDGE_DEVICE_ID_LEN 24

int flow_url_pipe_reader_fd = -1;
struct shmht *url_entries = NULL;
struct flow_url_entry *flow_url_cache = NULL;

unsigned int oat_hash(void *key)
{
  unsigned _ho_i;
  const unsigned char *_ho_key=(const unsigned char*)(key);
  unsigned int hashv = 0;
  for(_ho_i=0; _ho_i < SZ_FLOW_URL_KEY; _ho_i++) {
      hashv += _ho_key[_ho_i];
      hashv += (hashv << 10);
      hashv ^= (hashv >> 6);
  }
  hashv += (hashv << 3);
  hashv ^= (hashv >> 11);
  hashv += (hashv << 15);
  return hashv;
}

int
key_compar (void *c1, void *c2)
{
	return !bcmp (c1, c2, SZ_FLOW_URL_KEY);
}

void init_url_entries() {
  if (url_entries == NULL) {
    /* set up shared memory for urls */
    //printf("init_url_entries - config.print_cache_entries:%d\n", config.print_cache_entries);
    url_entries = create_shmht (SHM_TABLE_NAME, config.print_cache_entries, SZ_FLOW_URL_DATA, oat_hash, key_compar);
    /*
    printf("init_url_entries - url_entries:%p\n", url_entries);
    */
    if (url_entries != NULL) {
      shmht_flush(url_entries);
    }
  }
}

void init_url_reader() {
  if (flow_url_pipe_reader_fd <= 0) {
      flow_url_pipe_reader_fd = open(FIFO_NAME, O_RDONLY | O_NDELAY);
/*
      printf("%d - %d: flow_url_pipe_reader_fd: %d\n", getpid(), time(NULL), flow_url_pipe_reader_fd);
*/
      if (flow_url_pipe_reader_fd > 0) {
        Log(LOG_DEBUG, "DEBUG ( %s/%s ): Successfully opened FIFO(%s) - flow_url_pipe_reader_fd[%d].\n", config.name, config.type, FIFO_NAME, flow_url_pipe_reader_fd);
      }
  }
}

char *get_ip_str(struct in_addr in, char *s)
{
    inet_ntop(AF_INET, &in, s, INET6_ADDRSTRLEN);
    return s;
}

void process_url() {
  if (flow_url_pipe_reader_fd > 0) {
    char s[SZ_FLOW_URL_DATA];
    int num;
    do {
        if ((num = read(flow_url_pipe_reader_fd, s, SZ_FLOW_URL_DATA)) > 0) {
              struct flow_url_data *url_data = (struct flow_url_data *) s;
            if (url_entries != NULL) {
              struct flow_url_data *url_data = (struct flow_url_data *) s;

              struct flow_url_data clean_url_data;
              memset(&clean_url_data, 0, SZ_FLOW_URL_DATA);
              clean_url_data.key.client_ip.s_addr =  url_data->key.client_ip.s_addr;
              clean_url_data.key.ip = url_data->key.ip;
              strcpy(clean_url_data.key.path, url_data->key.path);
              strcpy(clean_url_data.key.protocol, url_data->key.protocol);
              clean_url_data.key.port = url_data->key.port;
              get_ip_str(url_data->key.client_ip, clean_url_data.client_ip_text);
              get_ip_str(url_data->key.ip, clean_url_data.ip_text);
              //printf("%s: %u->%u(%u):%s %s\n", clean_url_data.key.protocol, clean_url_data.key.client_ip, clean_url_data.key.ip, clean_url_data.key.port, 
                //clean_url_data.method, clean_url_data.key.path);
              size_t ret_size;
              struct flow_url_data *found = shmht_search (url_entries, (void *)&clean_url_data.key, SZ_FLOW_URL_KEY, &ret_size);
              if (found) {
                found->invocations++;
                found->ts = time(NULL);
              } else {
                strcpy(clean_url_data.method, url_data->method);
                strcpy(clean_url_data.hostname, url_data->hostname);
                
                clean_url_data.invocations = 1;
                clean_url_data.ts = time(NULL);
                int shmht_insert_ret = shmht_insert (url_entries, (void *)&clean_url_data.key, SZ_FLOW_URL_KEY, &clean_url_data, SZ_FLOW_URL_DATA);
              }
            }
        } else {
            s[num] = '\0';
        }
    } while (num > 0);
  }
}

int ip_compare(flow_url_client *a, flow_url_client *b) {
    return strcmp(a->ip_text, b->ip_text);
}

/* 
   Transform data keyed by client_ip, ip, port, method, and protocol into data 
   aggregated by ip, port, method, and protocol with a list of unique client_ip's.
*/
int aggregate_url(void *s)
{
  struct flow_url_entry *entry;
  struct flow_url_data *url_data = (struct flow_url_data *) s;
  struct flow_url_client *client;

  struct flow_url_key key;
  memset(&key, 0, SZ_FLOW_URL_KEY);
  key.port = url_data->key.port;
  key.ip = url_data->key.ip;
  strcpy(key.path, url_data->key.path);
  strcpy(key.protocol, url_data->key.protocol);


  HASH_FIND(hh, flow_url_cache, &key, SZ_FLOW_URL_KEY, entry);
  if (entry) {
    entry->invocations += url_data->invocations;
    if (entry->ts < url_data->ts) {
      entry->ts = url_data->ts;
    }
    //printf("purge update - %s %u(%d): %s %s invocations:%d ts:%d\n", entry->key.protocol, entry->key.ip, entry->key.port, entry->method, entry->key.path, entry->invocations, entry->ts);

    struct flow_url_client search_ip;
    strncpy(search_ip.ip_text, url_data->client_ip_text, INET6_ADDRSTRLEN);
    LL_SEARCH(entry->clients, client, &search_ip, ip_compare);
    if (!client) {
      client = malloc(SZ_FLOW_URL_CLIENT);
      strncpy(client->ip_text, url_data->client_ip_text, INET6_ADDRSTRLEN);
      LL_APPEND(entry->clients, client);
    }
  } else {
    entry = malloc(SZ_FLOW_URL_ENTRY);
    memset(entry, 0, SZ_FLOW_URL_ENTRY);
    entry->key.port = url_data->key.port;
    entry->key.ip = url_data->key.ip;
    strcpy(entry->ip_text, url_data->ip_text);
    strcpy(entry->key.path, url_data->key.path);
    strcpy(entry->key.protocol, url_data->key.protocol);
    strcpy(entry->method, url_data->method);
    strcpy(entry->hostname, url_data->hostname);
    entry->invocations = url_data->invocations;
    entry->ts = url_data->ts;
    strlcpy(entry->hostname, reverse_lookup_ia(&url_data->key.ip), NI_MAXHOST);

    client = malloc(SZ_FLOW_URL_CLIENT);
    strncpy(client->ip_text, url_data->client_ip_text, INET6_ADDRSTRLEN);
    LL_APPEND(entry->clients, client);

    HASH_ADD(hh, flow_url_cache, key, SZ_FLOW_URL_KEY, entry);
    //printf("purge insert - %s %u(%d): %s %s invocations:%d ts:%d\n", entry->key.protocol, entry->key.ip, entry->key.port, entry->method, entry->key.path, entry->invocations, entry->ts);
  }
  return 1;
}

void add_element(json_t *payload, json_t *element)
{
  json_object_update_missing(payload, element);
  json_decref(element);
} 

int publish_url_entry(struct flow_url_entry *entry) {
  //printf("purge - %s %s(%d): %s %s invocations:%d ts:%d\n", entry->key.protocol, entry->ip_text, entry->key.port, entry->method, entry->key.path, entry->invocations, entry->ts);

  int num_clients;
  struct flow_url_client *client, *client_tmp;
  LL_COUNT(entry->clients, client, num_clients);
  //printf("client_count: %d\n", num_clients);
  LL_FOREACH_SAFE(entry->clients, client, client_tmp) {
    LL_DELETE(entry->clients, client);
    free(client);
  }

  json_t *json_obj = json_object();
  add_element(json_obj, json_pack("{ss}", "edge_device_id", edge_device_id));
  add_element(json_obj, json_pack("{ss}", "ip", entry->ip_text));
  add_element(json_obj, json_pack("{ss}", "hostname", entry->hostname));
  add_element(json_obj, json_pack("{sI}", "port", entry->key.port));
  add_element(json_obj, json_pack("{ss}", "protocol", entry->key.protocol));
  add_element(json_obj, json_pack("{ss}", "method", entry->method));
  add_element(json_obj, json_pack("{sI}", "clients", num_clients));
  add_element(json_obj, json_pack("{sI}", "invocations", entry->invocations));

  char *path = entry->key.path;
  extract_token(&path, '?');
  add_element(json_obj, json_pack("{ss}", "path", entry->key.path));

  char tstamp_str[SRVBUFLEN];
  struct timeval tv;
  tv.tv_sec = time(NULL);
  tv.tv_usec = 0;
  compose_timestamp(tstamp_str, SRVBUFLEN, &tv, FALSE, FALSE, FALSE, TRUE);

  add_element(json_obj, json_pack("{ss}", "ts", tstamp_str));
  char *json_str = compose_json_str(json_obj);

  Log(LOG_INFO, "DEBUG ( %s/%s ): %s\n", MODULE_NAME, "publish_url_entry", json_str);
  int ret = p_amqp_publish_string(&amqpp_amqp_host, json_str);
  free(json_str);
  json_str = NULL;

  return 1;
}

void url_entries_purge(u_int64_t wtc_2, struct pkt_vlen_hdr_primitives *pvlen) {
  //printf("url_entries_purge: url_entries:%p edge_device_id:%p\n", url_entries, edge_device_id);
  if (url_entries != NULL && edge_device_id != NULL) {
    p_amqp_set_routing_key(&amqpp_amqp_host, "flow_url");
    int iterated_count = shmht_iterate (url_entries, aggregate_url);
    //printf("url_entries_purge: count:%d\n", iterated_count);

    struct flow_url_entry *entry, *entry_tmp;
    HASH_ITER(hh, flow_url_cache, entry, entry_tmp) {
      publish_url_entry(entry);
      HASH_DEL(flow_url_cache, entry);
      free(entry);
    }
    shmht_flush(url_entries);
  }
}
