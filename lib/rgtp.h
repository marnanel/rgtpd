/*
 * Distributed GROGGS
 *
 * Things defined by protocols, RFCs, etc.
 *
 * This file written by me, Ian Jackson, in 1993, 1994, 1995.
 * I hereby place it in the public domain.
 */

#ifndef RGTP_H
#define RGTP_H

/* Defined by the Assigned Numbers RFC (1060 and successors */
#define TCPPORT_RGTP    1431  /* Also in the RGTP spec */
#define TCPPORT_IDENT    113  /* Also in RFCs 931 and 1413 */

#define TCPIDENTLINE_MAXLEN 1024

/* Defined by the protocol spec */
#define TEXTLINE_MAXLEN        80
#define USERID_MAXLEN          75
#define INDEXENTRY_LEN        199 /* not including line separators */
#define TXRXLINE_MAXLEN       300 /* must be >= TEXTLINE_MAXLEN and INDEXENTRY_LEN */
#define ITEMID_LEN              8

/* Derived value */
#define SUBJECTININDEX_MAXLEN (INDEXENTRY_LEN - 8-1-8-1-ITEMID_LEN-1-\
                               USERID_MAXLEN-1-1-1 -1)

#endif
