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

#ifndef MISC_H
#define MISC_H

/* ul portion is *always* in *network* byte order */
#if 0
union longword { unsigned long ul; unsigned char uc[4]; };
#endif

void makelock(FILE*, int type, const char *filename);
void unlock(FILE*, const char *filename);
int ufclose(FILE*, const char *filename);

int scanhex(char **cmdp, int n, unsigned char *dest);
void sendhex(const unsigned char *p, int n);

#ifdef OWN_STRERROR
extern const char *strerror(int);
#endif

#ifdef OWN_WCOREDUMP
#define	WCOREDUMP(x) (((union __wait*)&(x))->__w_stopval == _WSTOPPED)
#endif

#endif
