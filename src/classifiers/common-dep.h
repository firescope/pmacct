/* This file aims to contain common definitions required by common.h,
   an effort to keep barebone and easy to read it. Thus the following
   definitions should remain untouched */

#define NSUBEXP  10
typedef struct regexp {
        char *startp[NSUBEXP];
        char *endp[NSUBEXP];
        char regstart;          /* Internal use only. */
        char reganch;           /* Internal use only. */
        char *regmust;          /* Internal use only. */
        int regmlen;            /* Internal use only. */
        char program[1];        /* Unwarranted chumminess with compiler. */
} regexp;

/* typedef void (*conntrack_helper)(time_t, struct packet_ptrs *); */
typedef void (*conntrack_helper)(time_t, void *);
