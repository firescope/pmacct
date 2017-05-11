/*
    CLASSIFIER:         RTP (Real Time Protocol)
    VERSION:            v1.0b
    AUTHORS:            Paolo Lucente

    NOTES:
    == v1.0b
    ! initial release
*/

#define __RTP_CLASSIFIER_C

/* includes */
#include "common.h"

char protocol[] = "rtp";
char type[] = "classifier";
char version[] = "1.0"; 

/*
 * RTP definitions (RFC 1889)
 */

/*
 * Current protocol version.
 */
#define RTP_VERSION    2

/*
 * RTP data header
 */
typedef struct {
//  u_int16_t version:2;	/* protocol version */
//  u_int16_t p:1;	/* padding flag */
//  u_int16_t x:1;	/* header extension flag */
//  u_int16_t cc:4;	/* CSRC count */
//  u_int16_t m:1;	/* marker bit */
//  u_int16_t pt:7;	/* payload type */
  u_int16_t init;	/* XXX: see commented fields */ 
  u_int16_t seq;	/* sequence number */
  u_int32_t ts;		/* timestamp */
  u_int32_t ssrc;	/* synchronization source */
  u_int32_t csrc[1];	/* optional CSRC list */
} rtp_hdr_t;

struct rtp_context {
  u_int16_t seq;
};

int init(void **extra)
{
  return 1;
}

u_int32_t classifier(struct pkt_classifier_data *data, int caplen, void **context, void **rev_context, void **extra)
{
  struct rtp_context *ctx = NULL;
  rtp_hdr_t *hdr = (rtp_hdr_t *) data->payload_ptr; 
  u_int16_t init;
  u_int8_t version, pt;

  init = ntohs(hdr->init);

  version = init >> 14;
  pt = init & 0x7f; 

  if ( version == 2 && (pt < 35 || pt >= 96) ) { /* Possibly, we are facing a RTP stream */ 
    if (!(*context)) {  /* We don't have enough data about the stream */
      ctx = malloc(sizeof(struct rtp_context));
      if (ctx) {
        ctx->seq = ntohs(hdr->seq);
        *context = ctx;
      }
      return 0;
    }
    else {
      ctx = (struct rtp_context *) *context;
      if (ntohs(hdr->seq) == ctx->seq+1) return 1;
    }
  }
 
  return 0;
} 
