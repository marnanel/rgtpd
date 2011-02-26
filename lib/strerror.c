/* Replacement for strerror() based on sys_errlist.
 * This file written by me, Ian Jackson, in 1993, 1994, 1995.
 * I hereby place it in the public domain.
 */

#include <stdlib.h>

extern char *sys_errlist[];
extern int sys_nerr;

const char *strerror(int n) {
  static char buf[20];
  if (n>=0 && n<sys_nerr) return sys_errlist[n];
  sprintf(buf,"%d",n);
  return buf;
}
