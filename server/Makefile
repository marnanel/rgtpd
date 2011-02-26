# Groggs server makefile
#
# This file written by me, Ian Jackson, in 1993, 1994, 1995.
# I hereby place it in the public domain.

ADMINBINS=udbmanage lockfile checkrgtpd
LIBSCRIPTS=regusermail userdb-backup updatesecret expire lock-updatesecret
PRIVLIBSCRIPTS=scanlog
TARGETS=groggsd $(ADMINBINS) $(LIBSCRIPTS) $(PRIVLIBSCRIPTS)
CPROGRAMS=groggsd udbmanage lockfile

include ../make.defs
include ../make.globaldefs
include .depend

install-all:	install install-daemon

install:	$(ADMINBINS) $(LIBSCRIPTS) $(PRIVLIBSCRIPTS)
		$(INSTALL_PROGRAM) $(ADMINBINS) $(adminbindir)
		$(INSTALL_PROGRAM) $(LIBSCRIPTS) $(servlibdir)
		$(INSTALL_PRIVPROGRAM) $(PRIVLIBSCRIPTS) $(servlibdir)

install-daemon:	groggsd
		-rm -f $(instserver)~*
		-mv $(instserver) $(instserver)~`date +%y%m%d%H%M%S`
		$(INSTALL_PROGRAM) groggsd $(instserver).new
		mv $(instserver).new $(instserver)

groggsd:	groggsd.o userdb.o $(STRERROR) ../lib/misc.o ../lib/md5.o
		$(CC) $(LDFLAGS) -o $@ $^

udbmanage:	udbmanage.o userdb.o $(STRERROR) ../lib/misc.o ../lib/sehandle.o
		$(CC) $(LDFLAGS) -o $@ $^

lockfile:	lockfile.o ../lib/misc.o ../lib/sehandle.o
		$(CC) $(LDFLAGS) -o $@ $^

clean:
		rm -f *.o

spotless:	clean
		rm -f $(CPROGRAMS) *~ *.bak
 
