/*
 * Distributed GROGGS  Copyright (C)1993 Ian Jackson
 *
 * User database handling
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

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>

#include "ehandle.h"
#include "misc.h"
#include "userdb.h"

const char *userdb_checkid(const char *src, char dest[USERID_MAXLEN]) {
  /* return is error string
   * src and dest may point to the same place
   * src is null-terminated
   * dest only null-terminated if there is room
   */
  int c;
  char *q;

  q= dest;
  if (strlen(src) > USERID_MAXLEN) return "too long";
  c= *src++;
  if (!isalnum(c)) return "doesn't start with an alphanumeric";
  do {
    if (!isalnum(c) && c!='.') return "contains non-alphanums before any @";
    *q++= c;
  } while ((c = *src++) != 0 && c!='@');
  if (c == '@') {
    do {
      if (isspace(c)) return "contains spaces";
      *q++= tolower(c);
    } while ((c= *src++) != 0);
  }
  if (q < dest+USERID_MAXLEN) *q=0;
  return 0;
}

u32 userdb_hash(const char userid[USERID_MAXLEN]) {
  u32 v= 0x4AFB;
  int i;
  const unsigned char *p;

  for (i=0,p=userid; i<USERID_MAXLEN && *p; i++,p++);
  while (i--) v= (v <<= 2)^(*--p);
  return v;
}

static void getentry(FILE *file, struct userentry *ret, const char *filename) {
  errno=0;
  if (fread(ret,sizeof(*ret),1,file)==1) return;
  if (ferror(file)) ohshite("User database `%s' unreadable",filename);
  else ohshit("User database `%s' changed under my feet",filename);
}

static int nextentry(FILE *file, int i, int n, const char *filename) {
  i++; if (i != n) return i;
  if (fseek(file,0,SEEK_SET))
    ohshite("Failed to rewind rewind user database `%s'",filename);
  return 0;
}

static void initbyuserid(const char *filename, const char *mode, int locktype,
                         const char userid[USERID_MAXLEN], int access,
                         FILE **file_r, int *initial_r, int *n_r) {
  FILE *file;
  int n,i;
  struct stat ustab;
  u32 hash;

  file= fopen(filename,mode);
  if (!file) ohshite("User database file `%s' inaccessible",filename);
  makelock(file,locktype,filename);
  if (fstat(fileno(file),&ustab)) ohshite("User database `%s' unstattable",filename);
  if (ustab.st_size % sizeof(struct userentry))
    ohshit("User database `%s' corrupt",filename);
  n= ustab.st_size / sizeof(struct userentry);
  if (n==0) ohshit("User database `%s' truncated",filename);
  hash= userdb_hash(userid);

  i= hash % n;
  if (fseek(file, i*sizeof(struct userentry), SEEK_SET))
    ohshite("User database `%s' unseekable",filename);

  *file_r= file;
  *initial_r= i;
  *n_r= n;
}

const struct userentry *userdb_find(const char *filename,
                                    const char userid[USERID_MAXLEN],
                                    int ac) {
  static struct userentry ue;
  int n, initial, i;
  FILE *file;

  initbyuserid(filename,"rb",F_RDLCK,userid,ac,&file,&initial,&n);
  i= initial;
  for(;;) {
    getentry(file,&ue,filename);
    if (!strncmp(userid,ue.userid,USERID_MAXLEN) &&
        (ac<0 || ue.access == ac)) { ufclose(file,filename); return &ue; }
    i= nextentry(file,i,n,filename);
    if (i == initial) { ufclose(file,filename); return 0; }
  }
}

int userdb_change(const char *filename, const struct userentry *uep, int create) {
  /* possible values for `create' are:
   *   0: never create a new record (return 1 if not already there).
   *   1: create a new record if required.
   *   2: fail (and return 1) if already exists (ie, force creation)
   *  -1: delete an existing record (return 1 if it doesn't exist).
   * return values are:
   *   0: OK
   *   1: Value for `create' prevented us from going ahead
   *   2: Wanted to create a new record, but there is no room.
   */
     
  static struct userentry ue;
  int n, initial, i, place;
  FILE *file;

  initbyuserid(filename,"r+b",F_WRLCK,uep->userid,uep->access,&file,&initial,&n);
  i= initial; place= -1;
  for(;;) {
    getentry(file,&ue,filename);
    if (!ue.userid[0]) {
      if (place==-1) place= i;
    } else if (!strncmp(uep->userid,ue.userid,USERID_MAXLEN)) /* &&
								(uep->access < 0 || uep->access == ue.access)) */ {
      if (create==2) { ufclose(file,filename); return 1; }
      place=i; break;
    }
    i= nextentry(file,i,n,filename);
    if (i == initial) {
      /* OK, we didn't find it.  We may have found a space, though */
      if (create<=0) { ufclose(file,filename); return 1; }
      if (place==-1) { ufclose(file,filename); return 2; }
      break;
    }
  }
  if (fseek(file,sizeof(struct userentry)*place,SEEK_SET))
    ohshite("User database `%s' unseekable for update",filename);
  if (create<0) {
    ue.userid[0]= 0;
    ue.secretbytes= 0;
    ue.disabled= 0;
    memset(ue.secret,0,SECRET_MAXBYTES);
    uep= &ue;
  } else {
    assert(uep->access >= 0);
  }
  errno=0; if (fwrite(uep,sizeof(*uep),1,file)!=1)
    ohshite("User database `%s' unwriteable",filename);
  if (ufclose(file,filename)) ohshite("User database `%s' uncloseable",filename);
  return 0;
}
