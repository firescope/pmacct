/*
    CLASSIFIER:		HTTP
    VERSION:		v1.0
    AUTHORS:		FireScope, Inc.

    NOTES:
    == v1.0
    ! initial release
*/

#define __HTTP_CLASSIFIER_C

/* includes */
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include "common.h"
#include "flow_url.h"

#define SSL_APPLICATION_DATA 0x17

/*
static u_int16_t SZ_FLOW_URL_DATA = sizeof(struct flow_url_data);
*/
char protocol[] = "unknown";
char type[] = "classifier";
char version[] = "1.0"; 
int flow_url_pipe_writer_fd = -1;
const char * const HTTP_METHODS[] = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT", "PATCH"};

struct my_iphdr
{
   u_int8_t     ip_vhl;         /* header length, version */
#define IP_V(ip)        (((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip)       ((ip)->ip_vhl & 0x0f)
   u_int8_t     ip_tos;         /* type of service */
   u_int16_t    ip_len;         /* total length */
   u_int16_t    ip_id;          /* identification */
   u_int16_t    ip_off;         /* fragment offset field */
#define IP_DF 0x4000                    /* dont fragment flag */
#define IP_MF 0x2000                    /* more fragments flag */
#define IP_OFFMASK 0x1fff               /* mask for fragmenting bits */
   u_int8_t     ip_ttl;         /* time to live */
   u_int8_t     ip_p;           /* protocol */
   u_int16_t    ip_sum;         /* checksum */
   struct in_addr ip_src;       /* source and destination addresses */
   struct in_addr ip_dst;
};

typedef u_int32_t tcp_seq;
struct my_tcphdr
{
    u_int16_t th_sport;         /* source port */
    u_int16_t th_dport;         /* destination port */
    tcp_seq th_seq;             /* sequence number */
    tcp_seq th_ack;             /* acknowledgement number */
#if defined IM_LITTLE_ENDIAN
    u_int8_t th_x2:4;           /* (unused) */
    u_int8_t th_off:4;          /* data offset */
#endif
#if defined IM_BIG_ENDIAN
    u_int8_t th_off:4;          /* data offset */
    u_int8_t th_x2:4;           /* (unused) */
#endif
    u_int8_t th_flags;
#define TH_FIN        0x01
#define TH_SYN        0x02
#define TH_RST        0x04
#define TH_PUSH       0x08
#define TH_ACK        0x10
#define TH_URG        0x20
    u_int16_t th_win;           /* window */
    u_int16_t th_sum;           /* checksum */
    u_int16_t th_urp;           /* urgent pointer */
};

struct ssl_t {
  u_int8_t protocol_type;
  u_int8_t major_version;
  u_int8_t minor_version;
  u_int16_t content_length;
}; 


/* Functions */
void init_url_writer() {
  if (flow_url_pipe_writer_fd <= 0) {
    unlink(FIFO_NAME);
    int state = mkfifo(FIFO_NAME, S_IFIFO | 0666);

    if(state < 0){
      printf("Error attempting to create FIFO(%s): %s\n", FIFO_NAME, strerror(errno));
    } else {
      /*
      flow_url_pipe_writer_fd = open(FIFO_NAME, O_WRONLY | O_NDELAY);
      */
      flow_url_pipe_writer_fd = open(FIFO_NAME, O_WRONLY);

      /* Uncomment below to troubleshoot errors in opening pipe */
      printf("%d - %d: classifier flow_url_pipe_writer_fd:%d err:%s\n", getpid(), time(NULL), flow_url_pipe_writer_fd, strerror(errno));
    }
  }
}

void print_payload(u_char *payload, int len) {
  int i;
  for (i = 0; i < len; i++, payload++) {
    char c = *(char *)payload;
    if (c >=32 && c <=126) {
      printf("%c", c);
    } else {
      printf("_", c);
    }
  }
  printf("\n");
}

int init(void **extra)
{
  return 1;
}

char *get_ip_str(struct in_addr in, char *s, size_t maxlen)
{
    memset(s, 0, maxlen);
    inet_ntop(AF_INET, &in, s, maxlen);
    return s;
}

void extract_src_dst(struct pkt_classifier_data *data, struct flow_url_data *url_data) {
    struct my_iphdr *iphdr = (struct my_iphdr *) data->l3_ptr;
    struct my_tcphdr *tcphdr = (struct my_tcphdr *) data->l4_ptr;

    memset(url_data, 0, SZ_FLOW_URL_DATA);
/*
    get_ip_str(iphdr->ip_src, url_data->key.client_ip, INET6_ADDRSTRLEN);
    get_ip_str(iphdr->ip_dst, url_data->key.ip, INET6_ADDRSTRLEN);
*/
    url_data->key.ip.s_addr = iphdr->ip_dst.s_addr;
    url_data->key.client_ip.s_addr = iphdr->ip_src.s_addr;
    url_data->key.port = ntohs(tcphdr->th_dport);
}

int validate_method(char *method)
{
  if (method) {
    int i;
    for (i = 0; i < 8; i++) {
      if (strncasecmp(HTTP_METHODS[i], method, 8) == 0) return 1;
    }
  }
  return 0;
}

u_int32_t classifier(struct pkt_classifier_data *data, int len, void **context, void **rev_context, void **extra)
{
  if (data->l4_proto == IPPROTO_TCP) {
    init_url_writer();
    struct flow_url_data url_data;
    u_char *ptr = (u_char *)data->payload_ptr;
    if (strncmp(ptr, "HTTP", 4) != 0 && strstr(ptr, "HTTP") != NULL) {
      /* Uncomment below to show the payload's content */
      /*
      print_payload(ptr, len);
      */

      if (flow_url_pipe_writer_fd > 0) {
        extract_src_dst(data, &url_data);
        memcpy(url_data.key.protocol, HTTP_PROTOCOL, PROTOCOL_LEN);
        char *token = strtok(ptr, " ");
	if (validate_method(token)) {
          memcpy(url_data.method, token, HTTP_METHOD_LEN);
          token = strtok(NULL, " ");
          if (token) {
            memcpy(url_data.key.path, token, PATH_MAX_LEN);
	  } else {
	    url_data.key.path[0] = '/';
          }
	  if (url_data.method && url_data.key.path) {
	    printf("%d - classifier - %s: %u->%u(%u):%s %s\n", getpid(), url_data.key.protocol, url_data.key.client_ip, url_data.key.ip, url_data.key.port,
		url_data.method, url_data.key.path);
	    write(flow_url_pipe_writer_fd, &url_data, SZ_FLOW_URL_DATA);
	    return 0;
	  }
        }
      }
    } else {
      struct ssl_t *ssl = (struct ssl_t *) ptr;
      if (ssl->protocol_type == SSL_APPLICATION_DATA && ssl->major_version == 3 && ssl->minor_version >=0 && ssl->minor_version <=3) {
        if (flow_url_pipe_writer_fd > 0) {
          extract_src_dst(data, &url_data);
          memcpy(url_data.key.protocol, HTTPS_PROTOCOL, PROTOCOL_LEN);
	  url_data.key.path[0] = '/';
          write(flow_url_pipe_writer_fd, &url_data, SZ_FLOW_URL_DATA);
	  return 0;
        }
      }
    }
  }

  return 1;
} 

