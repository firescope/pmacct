
#ifndef __FLOW_URL_H_
#define __FLOW_URL_H_

#include <netdb.h>

#define FIFO_NAME "/tmp/flow_url_pipe"
#define HTTP_PROTOCOL "http"
#define HTTPS_PROTOCOL "https"
#define HTTP_METHOD_LEN 8
#define PROTOCOL_LEN 8
#define PATH_MAX_LEN 256

struct flow_url_key {
  struct in_addr client_ip;
  struct in_addr ip;
  u_int16_t port;
  char protocol[PROTOCOL_LEN];
  char path[PATH_MAX_LEN];
};

struct flow_url_data {
  struct flow_url_key key;
  char client_ip_text[INET6_ADDRSTRLEN];
  char ip_text[INET6_ADDRSTRLEN];
  char hostname[NI_MAXHOST];
  char method[HTTP_METHOD_LEN];
  u_int16_t invocations;
  time_t ts;
};

static u_int16_t SZ_FLOW_URL_KEY = sizeof(struct flow_url_key);
static u_int16_t SZ_FLOW_URL_DATA = sizeof(struct flow_url_data);

#endif /* __FLOW_URL_H_ */
