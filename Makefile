# Top-level Groggs makefile
#
# This file written by me, Ian Jackson, in 1993, 1994, 1995.
# I hereby place it in the public domain.

SHELL=/bin/sh

OWNSUBDIRS= lib md5calc server
OTHERSUBDIRS= libdes-3.00
SUBDIRS= $(OWNSUBDIRS) $(OTHERSUBDIRS)

TARGETS= allsubdirs

include make.defs
include make.globaldefs

allsubdirs:
		set -e; for f in $(SUBDIRS); do cd $$f; echo $$f; $(MAKE); cd ..; done

install-all:
		$(MAKE) install
		$(MAKE) install-daemon

install:
		set -e; for f in $(SUBDIRS); do \
			cd $$f; echo $$f; $(MAKE) install; cd ..; \
		done

install-daemon:
		cd lib && $(MAKE)
		cd server && $(MAKE) install-daemon

depend:
		set -e; for f in $(OWNSUBDIRS); do \
			cd $$f; echo $$f; $(CC) $(CFLAGS) -E -M *.c >.depend.new ; \
			mv .depend.new .depend ; cd .. ; \
		done

clean:
		set -e; for f in $(SUBDIRS); do \
			cd $$f; echo $$f; $(MAKE) clean; cd ..; \
		done

spotless:	clean
		rm -f *~ *.bak
		set -e; for f in $(SUBDIRS); do \
			cd $$f; echo $$f; $(MAKE) spotless; cd ..; \
		done

realspotless:
		rm -f *~ *.bak
		set -e; for f in $(OWNSUBDIRS); do \
			cd $$f; echo $$f; touch .depend; \
			$(MAKE) spotless; rm -f .depend; cd ..; \
		done
		set -e; for f in $(OTHERSUBDIRS); do \
			cd $$f; echo $$f; $(MAKE) realspotless; cd ..; \
		done
