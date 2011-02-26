/*
 * Distributed GROGGS  Copyright 1993-1995 Ian Jackson
 *
 * Errorhandling - standalone
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
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ehandle.h"

void ohshite(const char *fmt, ...) {
  va_list al;
  char buf[250];
  int esave;

  esave= errno;
  va_start(al,fmt);
  vsprintf(buf,fmt,al);
  va_end(al);
  fputs("Fatal error: ",stderr);
  errno= esave; perror(buf);
  exit(2);
}

void ohshit(const char *fmt, ...) {
  va_list al;
  char buf[250];

  va_start(al,fmt);
  vsprintf(buf,fmt,al);
  va_end(al);
  fprintf(stderr,"Fatal error: %s\n",buf);
  exit(2);
}
