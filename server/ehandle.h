/*
 * Distributed GROGGS  Copyright 1993-1995 Ian Jackson
 *
 * Error handling
 *
 * This is a generic interface - there are two
 * implementations, one in groggsd.c and one in udbmanage.c
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

#ifndef EHANDLE_H
#define EHANDLE_H

void ohshite(const char *fmt, ...);
void ohshit(const char *fmt, ...);

#endif
