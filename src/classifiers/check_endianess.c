/* includes */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>

int main () {

void exit(int);

union
{
  long l;
  char c[sizeof (long)];
} u;

  u.l = 1;
  if (u.c[sizeof (long) - 1] == 1) printf("-DIM_BIG_ENDIAN\n");
  else printf("-DIM_LITTLE_ENDIAN\n"); 

  exit(0);
}
