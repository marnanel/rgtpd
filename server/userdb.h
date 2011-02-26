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

#ifndef USERDB_H
#define USERDB_H

#include "config.h"
#include "misc.h"

typedef unsigned int u32;

/* Don't change these without also changing the strings in groggsd.c:setstatus
 * and udbmanage.c:acs.
 * Also note that they are the same numbers as appear in the 23[0123] reply!
 */
enum accesslevel { al_none, al_read, al_write, al_edit, al_max=al_edit };

/* Don't change these without updating udbmanage.c:ids. */
enum user_identlevel { uil_none, uil_md5initial, uil_md5 };

struct userentry {
  char userid[USERID_MAXLEN];
  char access; /* enum accesslevel      these are made chars to avoid */
  char ident;  /* enum user_identlevel  byteorder problems            */
  char secretbytes;
  char disabled;
  unsigned char secret[SECRET_MAXBYTES];
  u32 lastref;
};

const struct userentry *userdb_find(const char *filename,
                                    const char userid[USERID_MAXLEN],
                                    int access);

int userdb_change(const char *filename, const struct userentry *uep, int create);
/* create=-1: delete  0: no creation  1: create if needed  2: create only */
/* return=0: success  1: failure - already/not there  2: failure - file full */

const char *userdb_checkid(const char *src, char dest[USERID_MAXLEN]);

u32 userdb_hash(const char userid[USERID_MAXLEN]);

#endif
