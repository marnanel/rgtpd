/*
 * Distributed GROGGS  Copyright 1993-1995 Ian Jackson
 *
 * Miscellaneous handy functions
 *
 *
 * This is free software; may redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is made available in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * A copy of the GNU General Public License can be found in the top-
 * level src directory.  Alternatively could write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA. 
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include "ehandle.h"
#include "misc.h"

#define FCNTL_LOCKING

#ifdef FCNTL_LOCKING

void makelock(FILE *file, int type, const char *filename) {

  /* if fcntl-style locking works, we can use it */

  struct flock fl;
  
  for (;;) {
    fl.l_type= type;
    fl.l_whence= SEEK_SET;
    fl.l_start= 0;
    fl.l_len= 1;
    if (fcntl(fileno(file),F_SETLKW,&fl) != -1) return;
    if (errno != EINTR) ohshite("Failed to lock %s (%s)",
                                filename,
                                type==F_RDLCK ? "read" :
                                type==F_WRLCK ? "write" : "?? ");
  }
  }
#else

void makelock(FILE *file, int type, const char *filename) {

  /* do this in an NFS-safe way. That means we can't distinguish
     between read and write locks... */

  char hbuff[100], tbuff[1024];
  pid_t mypid;
  struct stat sbuf;

  gethostname(hbuff,sizeof(hbuff));
  mypid=getpid();
  sprintf(tbuff,"%s.lock.%s.%i",filename,hbuff,mypid);

  /* tbuff now contains a unique file name for the lock */

  for (;;) {
    if (link(filename,tbuff)==-1) {
      ohshite("Failed to lock %s: lock filename %s",filename,tbuff);
    }
    /* check whether it's worked */
    stat(filename,&sbuf);
    if (sbuf.st_nlink==2) return;
    if (sbuf.st_nlink>2) unlink(tbuff); /* remove the attempted lock... */
    sleep(1); /* block */
  }
}
#endif

#ifdef FCNTL_LOCKING

void unlock(FILE *file, const char *filename) {

  /* no need to actually remove the lock in this situation */

}

#else

void unlock(FILE *file, const char *filename) {

  /* unlock the file locked by makelock */
  /* if we used fcntl style locking, this is unnecessary. Otherwise,
     this should be called before the file is closed, implicitly or
     explicitly. */

  char hbuff[100], tbuff[1024];
  pid_t mypid;
  
  gethostname(hbuff,sizeof(hbuff));
  mypid=getpid();
  sprintf(tbuff,"%s.lock.%s.%i",filename,hbuff,mypid);
  if (unlink(tbuff)==-1) {
    ohshite("Failed to remove lock file %s",tbuff);
  }
}

#endif

int ufclose(FILE *file, const char *filename) {

  unlock(file,filename);
  return fclose(file);
}

int scanhex(char **cmdp, int n, unsigned char *dest) {
  static const char hexdigits[]= "0123456789ABCDEF";
  int c, v;
  char *p, *e;
 
  p= *cmdp;
  while (n--) {
    c= *p++; e= strchr(hexdigits,toupper(c)); if (!e) return 0;
    v= (int)(e-hexdigits) << 4;
    c= *p++; e= strchr(hexdigits,toupper(c)); if (!e) return 0;
    *dest++ = v | (int)(e-hexdigits);
  }
  *cmdp= p;
  return 1;
}

void sendhex(const unsigned char *p, int i) {
  while (i--) printf("%02X",*p++);
}
