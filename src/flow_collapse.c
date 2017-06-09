#include <netdb.h>
#include <ifaddrs.h>
#include "pmacct.h"
#include "pmacct-defines.h"
#include "pmacct-data.h"
#include "network.h"
#include "once.h"
#include "plugin_common.h"
#include "amqp_common.h"
#include "uthash.h"
#include "utlist.h"

#define MODULE_NAME "flow_collapse"

/***** Data structure definitions *****/
struct flow_key {
  struct host_addr ip1;
  struct host_addr ip2;
};

struct chained_port {
  u_int16_t port;
  u_int8_t tcp_flags;
  struct chained_port *next;
};

struct port_entry {
  u_int16_t dst_port;
  struct chained_port *src_ports;
  u_int8_t proto;
  unsigned long weight;
  pm_counter_t packet_counter;
  pm_counter_t bytes_counter;
  struct host_addr *src_ip;
  char *src_fqdn;
  struct host_addr *dst_ip;
  char *dst_fqdn;
  struct port_entry *next;
};

struct port_bucket_entry {
  pm_counter_t total_packets;
  pm_counter_t total_bytes;
  struct port_entry *port_list;
  struct port_bucket_entry *next;
};

struct flow_entry {
  struct flow_key key;
  char host1[NI_MAXHOST];
  char host2[NI_MAXHOST];
  struct port_bucket_entry *port_bucket_list;
  UT_hash_handle hh;
};

struct registered_port_key {
  u_int16_t port;
  u_int8_t proto;
};

struct registered_port_entry {
  struct registered_port_key port_key;
  char name[16];
  UT_hash_handle hh2;
};

/***** Constants *****/
static const u_int32_t SZ_FLOW_KEY = sizeof(struct flow_key);
static const u_int32_t SZ_CHAINED_PORT = sizeof(struct chained_port);
static const u_int32_t SZ_PORT_ENTRY = sizeof(struct port_entry);
static const u_int32_t SZ_PORT_BUCKET_ENTRY = sizeof(struct port_bucket_entry);
static const u_int32_t SZ_FLOW_ENTRY = sizeof(struct flow_entry);
static const u_int32_t SZ_REGISTERED_PORT_KEY = sizeof(struct registered_port_key);
static const u_int32_t SZ_REGISTERED_PORT_ENTRY = sizeof(struct registered_port_entry);

/***** Global variables *****/
char *edge_device_id = NULL;
char *stamp_updated = NULL;
struct flow_entry *flow_cache = NULL;
struct registered_port_entry *registered_port_cache = NULL;
char collector_ip[16];
char *collector_name;

/***** Utility functions *****/
int chained_port_compare(struct chained_port *port1, struct chained_port *port2)
{
  return port1->port - port2->port;
}

int port_compare(struct port_entry *port1, struct port_entry *port2)
{
  return port1->dst_port - port2->dst_port;
}

// Sorting ports by most likelihood to be a server port.
long port_sort(struct port_entry *port1, struct port_entry *port2) 
{
  // Assuming server port will have most weight - which is the frequency of being targetted by other ports.
  long weight = port2->weight - port1->weight;
  if (weight == 0) {
    // Then assuming clients will receive more packets than servers.
    long packet_counter = port1->packet_counter - port2->packet_counter;
    //long packet_counter = port2->packet_counter - port1->packet_counter;
    if (packet_counter == 0) {
      // Also assuming clients will receive more bytes than servers.
      long bytes_counter = port1->bytes_counter - port2->bytes_counter;
      //long bytes_counter = port2->bytes_counter - port1->bytes_counter;
      return bytes_counter;
    } else return packet_counter;
  } else return weight;
}

void get_ordered_key(struct pkt_primitives *srcdst, struct flow_entry *flow_entry)
{
  // order addresses ascendingly for consistent hash values
  if (srcdst->src_ip.address.ipv4.s_addr < srcdst->dst_ip.address.ipv4.s_addr) {
    memcpy(&flow_entry->key.ip1, &srcdst->src_ip, HostAddrSz);   
    strncpy(flow_entry->host1, srcdst->src_fqdn, NI_MAXHOST);   
    memcpy(&flow_entry->key.ip2, &srcdst->dst_ip, HostAddrSz);   
    strncpy(flow_entry->host2, srcdst->dst_fqdn, NI_MAXHOST);   
  } else {
    memcpy(&flow_entry->key.ip1, &srcdst->dst_ip, HostAddrSz);   
    strncpy(flow_entry->host1, srcdst->dst_fqdn, NI_MAXHOST);   
    memcpy(&flow_entry->key.ip2, &srcdst->src_ip, HostAddrSz);   
    strncpy(flow_entry->host2, srcdst->src_fqdn, NI_MAXHOST);   
  }
}

char *ia_to_ip_text(struct in_addr *in, char *s)
{
  inet_ntop(AF_INET, in, s, INET6_ADDRSTRLEN);
  return s;
}

char *ha_to_ip_text(struct host_addr *ha, char *s)
{
  ia_to_ip_text(&ha->address.ipv4, s);
  return s;
}

struct flow_entry *get_flow_bucket(struct pkt_primitives *srcdst) 
{
  struct flow_entry *flow_entry = NULL;
  struct flow_entry flow_tmp;
  memset(&flow_tmp, 0, SZ_FLOW_ENTRY);

  get_ordered_key(srcdst, &flow_tmp);
  HASH_FIND(hh, flow_cache, &flow_tmp.key, SZ_FLOW_KEY, flow_entry);
  //printf("get_flow_bucket flow_entry:%p\n", flow_entry);
  if (!flow_entry) {
    flow_entry = malloc(SZ_FLOW_ENTRY);
    memset(flow_entry, 0, SZ_FLOW_ENTRY);
    memcpy(flow_entry, &flow_tmp, SZ_FLOW_ENTRY);
    HASH_ADD(hh, flow_cache, key, SZ_FLOW_KEY, flow_entry);
  }

  return flow_entry;
}

struct registered_port_entry *find_registered_port(u_int16_t port, u_int8_t proto)
{
  struct registered_port_key search_key;
  memset(&search_key, 0, SZ_REGISTERED_PORT_KEY);
  search_key.port = port;
  search_key.proto = proto;
  struct registered_port_entry *registered_port_entry_tmp;
  unsigned int hv;
  HASH_VALUE(&search_key, SZ_REGISTERED_PORT_KEY, hv);
  HASH_FIND(hh2, registered_port_cache, &search_key, SZ_REGISTERED_PORT_KEY, registered_port_entry_tmp);
  //printf("registered_port_cache[%p] port[%d] proto[%d] found[%p] name[%s] hash[%u]\n", registered_port_cache, port, proto, registered_port_entry_tmp, registered_port_entry_tmp == NULL ? "" : registered_port_entry_tmp->name, hv);
  return registered_port_entry_tmp;
}

void read_registered_ports()
{
  FILE* stream = fopen("/firescope/system_config/pmacct/service-names-port-numbers.csv", "r");
  char line[1024];
  char *end_ptr;
  int i=0;
  while (fgets(line, 1024, stream))
  {
    if (!strstr(line, "Unassigned")) {
      char *name_end = strchr(line, ',');
      if (name_end) {
        char *port_start = name_end + 1;
	u_int16_t port = strtoul(port_start, &end_ptr, 10);
	
	if (port > 0) {
          char *port_end = strchr(port_start, ',');
	  if (port_end) {
	    char *protocol_start = port_end + 1;
	    u_int8_t proto = 0;
            if (strncasecmp(protocol_start, "tcp", 3) == 0) {
	      proto = IPPROTO_TCP;
	    } else if (strncasecmp(protocol_start, "udp", 3) == 0) {
	      proto = IPPROTO_UDP;
	    }

            if (proto > 0) {
	      struct registered_port_entry *registered_port_entry = malloc(SZ_REGISTERED_PORT_ENTRY);
	      memset(registered_port_entry, 0, SZ_REGISTERED_PORT_ENTRY);
	      registered_port_entry->port_key.port = port;
	      registered_port_entry->port_key.proto = proto;

	      int name_len = name_end - line;
	      strncpy(registered_port_entry->name, line, name_len > 15 ? 15 : name_len);
	      HASH_ADD(hh2, registered_port_cache, port_key, SZ_REGISTERED_PORT_KEY, registered_port_entry);

	      //if (i++<100) {
	        //struct registered_port_entry *registered_port_entry_tmp = find_registered_port(port, proto);
	//	printf("adding port[%u] protocol[%d] name[%s] found[%p]\n", registered_port_entry->port_key.port, registered_port_entry->port_key.proto, registered_port_entry->name, registered_port_entry_tmp);
	      //}
	    }
	  }
	}
      }
    }
  }
  fclose(stream);

/*
  struct registered_port_entry *registered_port_entry, *registered_port_entry_tmp;
  HASH_ITER(hh2, registered_port_cache, registered_port_entry, registered_port_entry_tmp) {
    if (i++>100) break;
    if (registered_port_entry) {
      printf("adding port[%u] protocol[%d] name[%s] hashv[%u]\n", registered_port_entry->port_key.port, registered_port_entry->port_key.proto, registered_port_entry->name, registered_port_entry->hh2.hashv);
    }
  }
*/
}


int is_registered_port(u_int16_t port, u_int8_t proto)
{
  return find_registered_port(port, proto) == NULL ? 0 : 1;
}

void upsert_port(struct flow_entry *flow_entry, struct port_bucket_entry *port_bucket_entry, struct port_entry *port_entry, 
  u_int8_t proto, u_int16_t src_port, struct host_addr *host, u_int16_t dst_port, pm_counter_t packet_counter, pm_counter_t bytes_counter, u_int8_t tcp_flags)
{
  if (port_entry) {
    port_entry->packet_counter += packet_counter;
    port_entry->bytes_counter += bytes_counter;
  } else {
    port_entry = malloc(SZ_PORT_ENTRY);
    port_entry->proto = proto;
    port_entry->dst_port = dst_port;
    port_entry->packet_counter = packet_counter;
    port_entry->bytes_counter = bytes_counter;
    port_entry->src_ports = NULL;

    // determine src and dst for this port
    if (memcmp(&flow_entry->key.ip1, host, HostAddrSz) == 0) {
      port_entry->dst_ip = &flow_entry->key.ip1;
      port_entry->dst_fqdn = flow_entry->host1;
      port_entry->src_ip = &flow_entry->key.ip2;
      port_entry->src_fqdn = flow_entry->host2;
    } else {
      port_entry->dst_ip = &flow_entry->key.ip2;
      port_entry->dst_fqdn = flow_entry->host2;
      port_entry->src_ip = &flow_entry->key.ip1;
      port_entry->src_fqdn = flow_entry->host1;
    }

    LL_APPEND(port_bucket_entry->port_list, port_entry);
  }

  struct chained_port *chained_port;
  struct chained_port search_port;
  search_port.port = src_port;
  LL_SEARCH(port_entry->src_ports, chained_port, &search_port, chained_port_compare);
  if (!chained_port) {
    chained_port = malloc(SZ_CHAINED_PORT);
    memset(chained_port, 0, SZ_CHAINED_PORT);
    chained_port->port = src_port;
    chained_port->tcp_flags = tcp_flags;
    LL_APPEND(port_entry->src_ports, chained_port);
    int count;
    LL_COUNT(port_entry->src_ports, chained_port, count);
    port_entry->weight = count;
  }

  /*
  printf("    port:%u weight:%u packet_counter:%u bytes_counter:%u port_bucket_entry:%p\n", port_entry->dst_port, port_entry->weight, 
    port_entry->packet_counter, port_entry->bytes_counter, port_bucket_entry);
  */
}

void cleanup(struct flow_entry *flow_entry)
{
  struct port_bucket_entry *port_bucket_entry, *port_bucket_entry_tmp;
  struct port_entry *port_entry, *port_entry_tmp;
  struct chained_port *src_port, *src_port_tmp;
  LL_FOREACH_SAFE(flow_entry->port_bucket_list, port_bucket_entry, port_bucket_entry_tmp) {
    LL_FOREACH_SAFE(port_bucket_entry->port_list, port_entry, port_entry_tmp) {
      LL_FOREACH_SAFE(port_entry->src_ports, src_port, src_port_tmp) {
	LL_DELETE(port_entry->src_ports, src_port);
	free(src_port);
      }
      LL_DELETE(port_bucket_entry->port_list, port_entry);
      free(port_entry);
    }
    LL_DELETE(flow_entry->port_bucket_list, port_bucket_entry);
    free(port_bucket_entry);
  }
  HASH_DEL(flow_cache, flow_entry);
  free(flow_entry);
}

void get_host_ip(char *host) {
  struct ifaddrs *ifaddr, *ifa;
  if (getifaddrs(&ifaddr) == -1) {
    perror("getifaddrs");
  } else {
    //Walk through linked list, maintaining head pointer so we can free list later
    char *interface = config.dev == NULL ? "eth0" : config.dev;
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
      if (ifa->ifa_addr != NULL) {
	int family = ifa->ifa_addr->sa_family;
	if(strcmp( ifa->ifa_name, interface) == 0) {
	  if (family == AF_INET) {
	    int s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), host, 16, NULL, 0, NI_NUMERICHOST);
	    if (s != 0) {
              Log(LOG_ERR, "ERROR ( %s/%s ):getnameinfo() failed: %s\n", MODULE_NAME, "get_host_ip", gai_strerror(s));
	    } else break;
	  }
	}
      }
    }
    freeifaddrs(ifaddr);
  }
}

void compose_timestamp_utc(char *buf, int buflen, struct timeval *tv)
{
  time_t time1;
  struct tm *time2;

  time1 = tv->tv_sec;
  time2 = gmtime(&time1);
  strftime(buf, SRVBUFLEN, "%Y-%m-%d %H:%M:%S", time2);
}


void publish_port_entry(u_int64_t wtc, struct port_bucket_entry *port_bucket_entry, struct port_entry *port_entry, char *reason)
{
  char ip1[INET6_ADDRSTRLEN], ip2[INET6_ADDRSTRLEN];
  char ip_text[INET6_ADDRSTRLEN];
  ha_to_ip_text(port_entry->src_ip, ip1);
  ha_to_ip_text(port_entry->dst_ip, ip2);

  if (!reason) {
    Log(LOG_INFO, "DEBUG ( %s/%s ):    SKIPPED %s->%s(%u) protocol:%d weight:%u packet_counter:%u bytes_counter:%u\n", MODULE_NAME, "publish", 
      ip1, ip2, port_entry->dst_port, port_entry->proto, port_entry->weight, port_entry->packet_counter, port_entry->bytes_counter);
    return;
  }

  Log(LOG_INFO, "DEBUG ( %s/%s ):    PUBLISHED %s %s->%s(%u) protocol:%d weight:%u packet_counter:%u bytes_counter:%u\n", MODULE_NAME, "publish", 
    reason, ip1, ip2, port_entry->dst_port, port_entry->proto, port_entry->weight, port_entry->packet_counter, port_entry->bytes_counter);
  json_t *json_obj = json_object();
  add_element(json_obj, json_pack("{ss}", "label", edge_device_id));

  if (wtc & (COUNT_SRC_HOST|COUNT_SUM_HOST)) {
    ha_to_ip_text(port_entry->src_ip, ip_text);
    add_element(json_obj, json_pack("{ss}", "ip_src", ip_text));
    add_element(json_obj, json_pack("{ss}", "host_src", port_entry->src_fqdn));
  }
  if (wtc & COUNT_DST_HOST) {
    ha_to_ip_text(port_entry->dst_ip, ip_text);
    add_element(json_obj, json_pack("{ss}", "ip_dst", ip_text));
    add_element(json_obj, json_pack("{ss}", "host_dst", port_entry->dst_fqdn));
  }
  if (wtc & COUNT_DST_PORT) {
    add_element(json_obj, json_pack("{sI}", "port_dst", port_entry->dst_port));
    struct registered_port_entry *registered_port = find_registered_port(port_entry->dst_port, port_entry->proto);
    if (registered_port) {
      add_element(json_obj, json_pack("{ss}", "protocol_name", registered_port->name));
    } else {
      add_element(json_obj, json_pack("{ss}", "protocol_name", ""));
    }
  }
  if (wtc & COUNT_IP_PROTO) {
    if (!config.num_protos && (port_entry->proto < protocols_number))
      add_element(json_obj, json_pack("{ss}", "ip_proto", _protocols[port_entry->proto].name));
    else
      add_element(json_obj, json_pack("{sI}", "ip_proto", (json_int_t)port_entry->proto));
  }
  if (wtc & COUNT_TCPFLAGS) {
    //add_element(json_obj, json_pack("{sI}", "tcp_flags", port_entry->tcp_flags));
  }

  add_element(json_obj, json_pack("{ss}", "collector_name", collector_name));
  add_element(json_obj, json_pack("{ss}", "collector_ip", collector_ip));
  add_element(json_obj, json_pack("{ss}", "collapse_method", reason));
  add_element(json_obj, json_pack("{sI}", "packets", port_bucket_entry->total_packets));
  add_element(json_obj, json_pack("{sI}", "bytes", port_bucket_entry->total_bytes));

  if (!stamp_updated) {
    struct timeval tv;
    tv.tv_sec = time(NULL);
    tv.tv_usec = 0;
    stamp_updated = malloc(SRVBUFLEN);
    compose_timestamp_utc(stamp_updated, SRVBUFLEN, &tv);
  }
  add_element(json_obj, json_pack("{ss}", "stamp_updated", stamp_updated));

  char *json_str = compose_json_str(json_obj);
  int ret = p_amqp_publish_string(&amqpp_amqp_host, json_str);
  free(json_str);
  json_str = NULL;
}

void log_candidates(struct port_bucket_entry *port_bucket_entry)
{
  struct port_entry *port_entry;
  struct chained_port *src_port;
  char ports_text[200];
  int index = 0;

  Log(LOG_INFO, "DEBUG ( %s/%s ):      Candidates:\n", MODULE_NAME, "publish");
  LL_FOREACH(port_bucket_entry->port_list, port_entry) {
    if (port_entry && (index < 10 || (index % 10 == 0))) {
      char ip1[INET6_ADDRSTRLEN], ip2[INET6_ADDRSTRLEN];
      ha_to_ip_text(port_entry->src_ip, ip1);
      ha_to_ip_text(port_entry->dst_ip, ip2);

      memset(ports_text, 0, 200);
      int i = 0;
      LL_FOREACH(port_entry->src_ports, src_port) {
	if (i++ > 21) break;
	char port_text[10];
	sprintf(port_text, "%u(%d) ", src_port->port, src_port->tcp_flags);
	strcat(ports_text, port_text);
      }
      int count = 0;
      LL_COUNT(port_entry->src_ports, src_port, count);
      Log(LOG_INFO, "DEBUG ( %s/%s ):      %d:%s->%s(%u) protocol:%d weight:%u packet_counter:%u bytes_counter:%u src_ports[%d]: %s\n", MODULE_NAME, "publish", 
	index, ip1, ip2, port_entry->dst_port, port_entry->proto, port_entry->weight, port_entry->packet_counter, port_entry->bytes_counter, count, ports_text);
    }
    index++;
  }
}

int is_known_port(struct chained_port **known_ports, u_int16_t port) {
  struct chained_port search_port;
  search_port.port = port;
  struct chained_port *found_port = NULL;
  LL_SEARCH(*known_ports, found_port, &search_port, chained_port_compare);
  return found_port != NULL;
}

int is_known_ports(struct chained_port **known_ports, struct chained_port *ports) {
  struct chained_port *known_port = NULL;
  LL_FOREACH(ports, known_port) {
    if (known_port && is_known_port(known_ports, known_port->port)) {
      return 1;
    }
  }
  return 0;
}

void add_known_port(struct chained_port **known_ports, u_int16_t port) {
  if (!is_known_port(known_ports, port)) {
    struct chained_port *known_port = malloc(SZ_CHAINED_PORT);
    memset(known_port, 0, SZ_CHAINED_PORT);
    known_port->port = port;
    LL_APPEND(*known_ports, known_port);
  }
}

void add_known_ports(struct chained_port **known_ports, struct chained_port *ports) {
  struct chained_port *known_port = NULL;
  LL_FOREACH(ports, known_port) {
    if (known_port) {
      add_known_port(known_ports, known_port->port);
    }
  }
}

void clear_known_ports(struct chained_port **known_ports, char *type) {
  struct chained_port *known_port = NULL, *known_port_tmp = NULL;
  LL_FOREACH_SAFE(*known_ports, known_port, known_port_tmp) {
    if (known_port) {
      LL_DELETE(*known_ports, known_port);
      free(known_port);
    }
  }
}

void prune(struct port_entry *port_list, struct chained_port *src_port, u_int16_t candidate_dst_port)
{
  if (src_port) {
    struct port_entry *port_entry = NULL, *port_entry_tmp = NULL;
    LL_FOREACH_SAFE(port_list, port_entry, port_entry_tmp) {
      if (port_entry && candidate_dst_port != port_entry->dst_port) {
	// remove candidate_port->dst_port from the prune port's src_ports
	struct chained_port search_chained_port;
	search_chained_port.port = candidate_dst_port;
	struct chained_port *src_port = NULL;
	LL_SEARCH(port_entry->src_ports, src_port, &search_chained_port, chained_port_compare);
	if (src_port) {
	  LL_DELETE(port_entry->src_ports, src_port);
	  free(src_port);
	  if (port_entry->weight > 0) port_entry->weight--;
	}
      }
    }
  }
}

void pre_publish()
{
  if (config.acct_type == ACCT_NF) {
    collector_name = "nfacctd";
  } else if (config.acct_type == ACCT_SF) {
    collector_name = "sfacctd";
  } else {
    collector_name = "pmacctd";
  }

  get_host_ip(collector_ip);
  if (strlen(collector_ip) == 0) {
   strcpy(collector_ip, "unknown");
  }
}

void publish(u_int64_t wtc, struct flow_entry *flow_entry)
{
  char ip1[INET6_ADDRSTRLEN], ip2[INET6_ADDRSTRLEN];
  char ip_text[INET6_ADDRSTRLEN];
  ha_to_ip_text(&flow_entry->key.ip1, ip1);
  ha_to_ip_text(&flow_entry->key.ip2, ip2);
  Log(LOG_INFO, "DEBUG ( %s/%s ): flow bucket for ip1[%s] ip2[%s]:\n", MODULE_NAME, "publish", ip1, ip2);
  struct chained_port *src_port = NULL;
  struct port_bucket_entry *port_bucket_entry = NULL;
  LL_FOREACH(flow_entry->port_bucket_list, port_bucket_entry) {
    if (port_bucket_entry) {
      struct port_entry *candidate_port = NULL;
      int count = 0;
      LL_COUNT(port_bucket_entry->port_list, candidate_port, count);
      if (count > 1) {
	struct chained_port *known_client_ports = NULL, *known_server_ports = NULL;
	// sort weightiest first
	int published_bucket = 0;
	LL_SORT(port_bucket_entry->port_list, port_sort);
	LL_FOREACH(port_bucket_entry->port_list, candidate_port) {
	  int published_port = 0;
	  if (candidate_port &&
	   !(is_known_port(&known_client_ports, candidate_port->dst_port) || is_known_ports(&known_server_ports, candidate_port->src_ports))) {
	    
	    if (find_registered_port(candidate_port->dst_port, candidate_port->proto) != NULL) {
	      publish_port_entry(wtc, port_bucket_entry, candidate_port, "known port");
	      add_known_ports(&known_client_ports, candidate_port->src_ports);
	      add_known_port(&known_server_ports, candidate_port->dst_port);
	      published_bucket = published_port = 1;
	    } else if (config.acct_type == ACCT_PM && candidate_port->proto == IPPROTO_TCP) {
	      // For TCP, verify at least one source port sent a SYN to the candidate's port while the candidate did not send SYN to source port
	      struct chained_port *syn_src_port = NULL;
	      LL_FOREACH(candidate_port->src_ports, syn_src_port) {
		if (syn_src_port && (syn_src_port->tcp_flags & TH_SYN)) {
		  struct port_entry search_port;
		  search_port.dst_port = syn_src_port->port;
		  struct port_entry *synched_port = NULL;
		  LL_SEARCH(port_bucket_entry->port_list, synched_port, &search_port, port_compare);
		  if (synched_port) {
		    struct chained_port search_chained_port;
		    search_chained_port.port = candidate_port->dst_port;
		    struct chained_port *unsyn_src_port = NULL;
		    LL_SEARCH(synched_port->src_ports, unsyn_src_port, &search_chained_port, chained_port_compare);
		    if(unsyn_src_port && !(unsyn_src_port->tcp_flags & TH_SYN)) {
		      publish_port_entry(wtc, port_bucket_entry, candidate_port, "TCP sync");
		      add_known_ports(&known_client_ports, candidate_port->src_ports);
		      add_known_port(&known_server_ports, candidate_port->dst_port);
		      published_bucket = published_port = 1;
		      break;
		    }
		  }
		}
	      }
	    } 
	    if (!published_port && candidate_port->weight > 1) {
	      // publish by weight
	      publish_port_entry(wtc, port_bucket_entry, candidate_port, "weighted");
	      add_known_ports(&known_client_ports, candidate_port->src_ports);
	      add_known_port(&known_server_ports, candidate_port->dst_port);
	      published_bucket = published_port = 1;
	    }
	  }
	}
	if (!published_bucket) {
	  // Not yet published because all ports are one-way and weighed 1
	  LL_FOREACH(port_bucket_entry->port_list, candidate_port) {
	    if (candidate_port) {
	      // allow only known destination ports
	      if (find_registered_port(candidate_port->dst_port, candidate_port->proto) != NULL) {
	        publish_port_entry(wtc, port_bucket_entry, candidate_port, "one-way known port");
	      } else {
	        // skip unknown one-way port
	        publish_port_entry(wtc, port_bucket_entry, candidate_port, "one-way unknown port");
	      }
	    /*
	      struct chained_port *src_port = NULL;
	      LL_FOREACH(candidate_port->src_ports, src_port) {
		// publish unknown that are not responses to well known ports
		if (src_port && find_registered_port(src_port->port, candidate_port->proto) == NULL) {
		  publish_port_entry(wtc, port_bucket_entry, candidate_port, "unknown");
		  break;
		}
	      }
	    */
	    }
	  }
	}
	  
	log_candidates(port_bucket_entry);
	clear_known_ports(&known_client_ports, "client");
	clear_known_ports(&known_server_ports, "server");
      } else {
        // handle one way flow, only allow traffic to inclusive range on IANA port
	if (candidate_port && find_registered_port(candidate_port->dst_port, candidate_port->proto) != NULL) {
	  publish_port_entry(wtc, port_bucket_entry, candidate_port, "one-way known port");
        }
      }
    }
  }
}

/***** Public entry points *****/
void collapse_flows(struct chained_cache *queue[], int index)
{
  int j;
  struct flow_entry *flow_entry;
  if (config.what_to_count_2 & COUNT_LABEL) {
    for (j = 0; j < index; j++) {
      if (queue[j]->valid != PRINT_CACHE_COMMITTED) continue;

      if (!edge_device_id) {
        vlen_prims_get(queue[j]->pvlen, COUNT_INT_LABEL, &edge_device_id);
      }

      struct pkt_primitives *srcdst = &queue[j]->primitives;

      flow_entry = get_flow_bucket(srcdst);
      if (!flow_entry) {
	// FATAL: can't allocate bucket
	return;
      } 

      struct port_entry *src_port_entry = NULL;
      struct port_entry *dst_port_entry = NULL;
      struct port_bucket_entry *port_bucket_entry;
      LL_FOREACH(flow_entry->port_bucket_list, port_bucket_entry) {
	if (port_bucket_entry) {
	  struct port_entry search_port;
	  search_port.dst_port = srcdst->src_port;
	  LL_SEARCH(port_bucket_entry->port_list, src_port_entry, &search_port, port_compare);
	  search_port.dst_port = srcdst->dst_port;
	  LL_SEARCH(port_bucket_entry->port_list, dst_port_entry, &search_port, port_compare);

	  if (src_port_entry || dst_port_entry) break;
	}
      }

      if (!src_port_entry && !dst_port_entry) {
	// add port_bucket_entry
	port_bucket_entry = malloc(SZ_PORT_BUCKET_ENTRY);
	memset(port_bucket_entry, 0, SZ_PORT_BUCKET_ENTRY);
	LL_APPEND(flow_entry->port_bucket_list, port_bucket_entry);

        /*
	char ip1[INET6_ADDRSTRLEN], ip2[INET6_ADDRSTRLEN];
	char ip_text[INET6_ADDRSTRLEN];
	ha_to_ip_text(&srcdst->src_ip, ip1);
	ha_to_ip_text(&srcdst->dst_ip, ip2);
	printf("src[%s] dst[%s]: new port bucket[%p] sport[%u] dport[%u]\n", ip1, ip2, port_bucket_entry, srcdst->src_port, srcdst->dst_port);
	*/
      }

      // update total counter stats across all ports for the port bucket
      port_bucket_entry->total_bytes += queue[j]->bytes_counter;
      port_bucket_entry->total_packets += queue[j]->packet_counter;

      // for individual port stats, add counters to destinations only
      upsert_port(flow_entry, port_bucket_entry, dst_port_entry, srcdst->proto, srcdst->src_port, &srcdst->dst_ip, srcdst->dst_port, 
	queue[j]->packet_counter, queue[j]->bytes_counter, queue[j]->tcp_flags);
    }
  } else {
    Log(LOG_ERR, "ERROR ( %s/%s ): Missing label keyword in aggregates list -  needed for edge device id\n", MODULE_NAME, "collapse_flows");
  }

}

void purge_flows()
{
  struct flow_entry *flow_entry, *flow_entry_tmp;

  if (flow_cache != NULL) read_registered_ports();
  pre_publish();
  HASH_ITER(hh, flow_cache, flow_entry, flow_entry_tmp) {
    if (flow_entry) {
      publish(config.what_to_count, flow_entry);
      cleanup(flow_entry);
    }
  }

  struct registered_port_entry *registered_port_entry, *registered_port_entry_tmp;
  HASH_ITER(hh2, registered_port_cache, registered_port_entry, registered_port_entry_tmp) {
    if (registered_port_entry) {
      HASH_DELETE(hh2, registered_port_cache, registered_port_entry);
      free(registered_port_entry);
    }
  }
  free(stamp_updated);
}
