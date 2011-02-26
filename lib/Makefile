# Groggs library code makefile
#
# This file written by me, Ian Jackson, in 1993, 1994, 1995.
# I hereby place it in the public domain.

include ../make.defs
include ../make.globaldefs
include .depend

TARGETS= md5.o misc.o sehandle.o $(STRERROR)

install:	$(TARGETS)
		$(INSTALL_DATA) rgtp.h $(infodir)/rgtp.h

all:		$(TARGETS)

clean:
		rm -f *.o

spotless:	clean
		rm -f $(TARGETS) *~ *.bak
