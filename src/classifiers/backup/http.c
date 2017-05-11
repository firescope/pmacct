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
#include "common.h"

char protocol[] = "http";
char type[] = "classifier";
char version[] = "1.0"; 

int init(void **extra)
{
  return 1;
}

u_int32_t classifier(struct pkt_classifier_data *data, int len, void **context, void **rev_context, void **extra)
{
  int i;
  if (data->l4_proto == IPPROTO_TCP) {
    u_char *ptr = (u_char *)data->payload_ptr;
    if (strstr(ptr, "HTTP") != NULL) {
/*
      for (i = 0; i < data->plen; i++, ptr++) {
          char c = *(char *)ptr;
          if (c == '\0')
              break;

          if (c >=32 && c <=126) {
            printf("%c", c);
          } else {
            printf(" ");
          }
      }
      printf("\n");
*/


      return 0;
    }
  }

  return 1;
} 
