/*
 * Distributed GROGGS  Copyright (C)1993 Ian Jackson
 *
 * Compile-time configuration
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

#ifndef CONFIG_H
#define CONFIG_H

#include "rgtp.h"

#define REGUWARNING_STRING "\
250 Warning message follows\r\n\
 This procedure is the application for both posting access to GROGGS\r\n\
 and membership of the GROGGS society.\r\n\
The next USER command will record\r\n\
your claimed address and send your cryptographic key by email.\r\n\
 \r\n\
 Please give the userid you wish to use, including mail domain name.\r\n\
 You may abbreviate <x>.cam.ac.uk to just <x> and cam.ac.uk to cam).\r\n\
 Your calling identity is being recorded.  Do not give a false userid.\r\n\
 Doing so is a breach of the Rules and of the Computer Misuse Act,\r\n\
 and will be investigated and reported to the appropriate authorities.\r\n\
If you do not wish to proceed with the registration issue a QUIT command.\r\n\
.\r\n"
  
#define NEWUSERACCESS          al_write
  
/* Program names */
#define PREFIX_DIR             "/home/mjh22/groggs/"
#define BIN_DIR                PREFIX_DIR "bin/Linux/"
#define ADMINBIN_DIR           PREFIX_DIR "sbin/"
#define PROGLIB_DIR            PREFIX_DIR "lib/server/"
#define GNUDIFF_PROGRAM        "/usr/bin/diff"
#define REGUSER_PROGRAM        PROGLIB_DIR "regusermail"
#define DAEMON_PROGRAM         PROGLIB_DIR "rgtpd"
#define UDBM_PROGRAM           ADMINBIN_DIR "udbmanage"

/* Spool filename prefixes and suffixes */
#define SPOOL_DIR              "/home/mjh22/groggs/spool/"
#define EDITED_FILENAMESFX     ".edited"
#define WITHDRAWN_FILENAMESFX  ".withdrawn"

/* Filenames relative to the spool directory */
#define EDITLOCK_FILENAME      "editlock"
#define EDITLOG_FILENAME       "editlog"
#define LOG_FILENAME           "log/log"
#define IDARBITER_FILENAME     "idarbiter"
#define SEQUENCE_FILENAME      "sequence"
#define INDEX_FILENAME         "index"
#define ITEM_FILENAMEPFX       "item/"
#define MOTD_FILENAME          "motd"
#define RANDOMSTUFF_FILENAME   "secretseed"
#define USERDB_FILENAME        "userdatabase"

/* You might want to change these */
#define DATESTRING_FORMAT    "%H.%M on %a %d %b"
#define DATESTRING_MAXLEN    50
#define TCPIDENT_TIMEOUT     20   /* seconds */
#define REPLY_MAXLEN       3000
#define CONTRIB_MAXLEN     7000   /* must be more than REPLY_MAXLEN */
#define ITEM_MAXLEN       14000
#define STARTINGYEAR         85   /* +1900; see the definition of tm_year */
#define INPUTLINE_MAXLEN    (TXRXLINE_MAXLEN+3)
#define UDBM_MAXARGS         20
#define INACTIVITY_TIMEOUT       3600   /* in seconds, so 60 minutes */
#define EDITORINACTIVITY_TIMEOUT 1200   /* in seconds, so 20 minutes */
#define DATA_TIMEOUT              300   /* in seconds, so 5 minutes */
#define DEFAULT_ACCESS    al_write
#define DEFAULT_SECRETBYTES   8         /* MUST be <= SECRET_MAXBYTES */
#define RANDOMSTUFF_LOW     128         /* min amount of random to keep */
#define RANDOMSTUFF_HIGH   1024         /* max amount to keep (bytes) */
#define RANDOMSTUFF_WARN    256         /* log an alert when it gets this bad */

/* If you change this the user database format changes,
   so you'll have to make a new one */
#define SECRET_MAXBYTES      16

/* Strings you probably won't want to change, but you may if you wish */
#define SUBJECT_PFXSTRING      "Subject: "
#define LONGGROGNAME_PFXSTRING "From "
#define LONGUSERID_PFXSTRING   "User " /* } you MUST update these */
#define LONGUSERID_PFXSTRINGLEN 5      /* } two together          */
#define ITEMSTART_PFXSTRING    "Item "
#define REPLYSTART_PFXSTRING   "Reply "

#if USERID_MAXLEN > (TEXTLINE_MAXLEN-LONGUSERID_PFXSTRINGLEN)
#error LONGUSERID_PFXSTRING is too long
#endif
#define TCPPORT_DEFAULT       TCPPORT_RGTP
#define ITEM_MAXFILENAMELEN   (sizeof(ITEM_FILENAMEPFX)+ITEMID_LEN)
#define INDEXENTRY_LENINF     (INDEXENTRY_LEN+1)

#define UMASK_ADD             007 /* deny rwx to other */

#endif
