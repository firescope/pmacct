/*
    CLASSIFIER:		eDonkey/eMule 
    VERSION:		v1.0b
    AUTHORS:		Paolo Lucente 

    NOTES:
    == v1.0b
    ! initial release
*/

#define __EDONKEY_CLASSIFIER_C

/* includes */
#include "common.h"

char protocol[] = "edonkey";
char type[] = "classifier";
char version[] = "1.0"; 

struct edk_context {
  u_int16_t code;
};

#define REQUEST_OP	1
#define REPLY_OP	2

int init(void **extra)
{
  return 1;
}

u_int32_t classifier(struct pkt_classifier_data *data, int len, void **context, void **rev_context, void **extra)
{
  struct edk_context *edkc = NULL;
  u_char *ptr = (u_char *)data->payload_ptr;
  u_int32_t edk_size = *(ptr+1);

  if (data->l4_proto == IPPROTO_UDP) {
    if (ptr[0] == 0xe3) {
      /* We try to rely on the fact that bytes 1-4 encode the size
         of the remainder of the message */
      if (edk_size == len - 5) return 1;

      /* We try to match some requests that may have been sent to
	 the server */
      if (ptr[1] == 0x24 || ptr[1] == 0x9A || ptr[1] == 0x96 ||
	  ptr[1] == 0x92 || ptr[1] == 0x98 || ptr[1] == 0xA2) {
	if (!(*context)) {
	  edkc = malloc(sizeof(struct edk_context));
	  if (!edkc) return 0;
	  
	  edkc->code = REQUEST_OP;
	  *context = edkc;
	  return 0;
	}
      } 

      /* We try to match some server replies; then, if we are able
	 to find a request code in the reverse context, we issue a
	 match */
      if (ptr[1] == 0x16 || ptr[1] == 0x9B || ptr[1] == 0x97 ||
	  ptr[1] == 0x99 || ptr[1] == 0xA3) {
        if (*rev_context && ((struct edk_context *) *rev_context)->code == REQUEST_OP)
	  return 1;
      }
    }
  }
  else if (data->l4_proto == IPPROTO_TCP) {
    if (ptr[0] == 0xe3 || ptr[0] == 0xc5) {
      if (edk_size == len - 5) return 1;
    } 
  }

  return 0;
} 
