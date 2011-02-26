AC_PREREQ([2.59])

AC_INIT([rgtpd], [0.1.0], [http://www.groggs.group.cam.ac.uk])

AC_CONFIG_MACRO_DIR([m4])

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AM_INIT_AUTOMAKE([1.8 -Wno-portability])

AM_PROG_LIBTOOL
AM_CONFIG_HEADER(config.h)
AM_PROG_MKDIR_P

AC_PROG_CC
AC_PROG_CC_STDC

AC_OUTPUT( Makefile \
	server/Makefile \
	)

