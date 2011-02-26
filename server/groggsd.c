/*
 * Distributed GROGGS  Copyright (C)1993/1994 Ian Jackson
 *
 * Daemon main program
 *
 * Conforms to protocol revision 22
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

#include <sys/types.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/wait.h>

#include "config.h"
#include "ehandle.h"
#include "md5.h"
#include "userdb.h"
#include "misc.h"

/* Global variables (may be modified by server after forking children) */
static int debugserver;           /* number of times we were given the -debug flag */
/* debug=1 means standard interactive debug, debug=2 means noninteractive logged   */
static unsigned long servseq;     /* serial number for each server subprocess      */
struct sockaddr_in calleraddr;    /* child's server socket peer (client) address   */
static sig_atomic_t wantrestart;  /* caught a SIGUSR2 - restart when convenient    */
static long mypid;                /* for use in messages, &c                       */

/* Per-session variables */
static int debuglevel;            /* how much debugging - range from 0 to 9; only   *
                                   * available if the dangerous -debug switch       *
                                   * was given.                                     */
static int supertrace;            /* log all commands and responses from now on     */
static unsigned int alarmclosefd; /* on SIGALRM close this fd and set to -1         */
static int slave;                 /* per-client socket fd                           */
static int port;                  /* port we are listening or must listen on        */
static char clientid[100];        /* client's IP number and port, for logging       */
static char loglinebuf[INPUTLINE_MAXLEN+5]; /* use this to log the cmd line if we   *
                                   * decide we want to somewhere; empty string      *
                                   * means we've already logged this command        */

/*
 * Continuation/reply/edit states:
 * 			Initial/ Normal  May	May	Editing	Editing	
 *			Normal   +EDLK   cont	cont	index	item	
 *			                	+EDLK
 *			------- ------- -------	-------	-------	-------	
 * maycontinue		false	false	TRUE	TRUE	false	false	
 * saveditemid		?	?	itemid	itemid	""	itemid	
 * edit			NULL	set	NULL	set	set	set	
 * lenbeforeedit	-1	-1	-1	-1	set	set	
 */

static int maycontinue; 		  /* a continuation (CONT) is allowed now,   *
                                           * 0 for false or 1 for true.              */
static char saveditemid[ITEMID_LEN+1]=""; /* itemid which may be continued (if       *
					   * maycontinue is set) or which is being   *
                                           * edited (if lenbeforeedit != -1) or the  *
                                           * empty string (if we're editing the      *
                                           * index (again, lenbeforeedit != -1).     */
static FILE *edit=0;                      /* open filehandle onto the edit lock file *
                                           * if we have an EDLK, otherwise NULL      */
static unsigned long lenbeforeedit= -1;   /* -1 if we are not editing anything; if   *
                                           * we are this is the length it was when   *
                                           * we sent it in response to EDIT or EDIX. */

/*
 * Registration/user login/access control states:
 *                   Initial/       REGU           After disputed Logged
 *                   normal         accepted       ALVL/USER,     in
 *                                                 expecting AUTH
 *                   -------------- -------------- -------------- --------------
 * registration      false          TRUE           false          false
 * alevel            al_none        al_none        current        set
 * userid            ""             ""             set (claimed)  set
 * identue.userid    ""             ""             requested      ""
 * identue.access    ?              ?              requested      ?
 * servernonce       ?              ?              set            ?
 */

static int registration;                /* We have accepted a REGU (0=false, 1=TRUE. */
static enum accesslevel alevel;         /* The currently allowed access level.       */
static char userid[USERID_MAXLEN+1]=""; /* The userid claimed by the client.         */
struct userentry identue;               /* User database structure corresponding to  *
                                         * username and access level claimed by user *
                                         * if we're doing an authentication.  If not *
                                         * .userid is "" and other fields undefined. */
unsigned char servernonce[16];          /* If we're doing an auth, our nonce.        */

/*
 * Data submission states:
 *                Initial/       Item/          Edited         Edited
 *                No data        reply          Index          Item
 *                -------------- -------------- -------------- --------------
 * data           NULL           set            set            set
 * grogname       ?              set            ""             status (ignored)
 * dstab          ?              set            set            set
 */

static FILE *data=0;                      /* If DATA has been sent, the open file    *
                                           * containing the data, otherwise NULL.    */
static char grogname[INPUTLINE_MAXLEN+5]; /* The grogname in item or reply DATA;     *
                                           * "" for revised (edited) index data;     *
                                           * the status line (which will be ignored  *
                                           * by EDCF) for revised item data;         *
                                           * undefined if no data sent.              */
static struct stat dstab;                 /* If data has been sent, the result of    *
                                           * fstat on the data file after writing    *
                                           * the data to it, otherwise undefined.    */

/*
 * Errorhandling
 */

enum loglevel { ll_debug, ll_ident, ll_trace, ll_alert, ll_error, ll_fatal };
const char *const loglevels[]= {
  "debug", "ident", "Trace", "ALERT", "ERROR", "FATAL"
};

static time_t gettime(void) {
  time_t t;
  t= time((time_t*)0);
  if (t == (time_t)-1) {
    perror("groggsd: ERROR getting time for log");
    fputs("484 Severe system problem - unable to get the time\r\n",stdout);
    exit(1);
  }
  return t;
}

static void tcpident(void);
static void checkstderr(void);
static void setsupertrace(void);

static void vlog(enum loglevel level, const char *fmt, va_list al) {
  struct tm *tmp;
  char buf[100];
  time_t t;

  checkstderr();
  t= gettime();
  tmp= gmtime(&t);
  if (!tmp) {
    perror("groggsd: ERROR converting time for log");
    fputs("484 Severe system problem - unable to convert the time\r\n",stdout);
    exit(1);
  }
  strftime(buf,99,"%d.%m.%y %H:%M:%S %Z",tmp); buf[99]=0;

  fprintf(stderr, "%s %s groggsd%ld %s : ", buf, loglevels[level], mypid, clientid);
  vfprintf(stderr,fmt,al);
  fputc('\n',stderr);
  fflush(stderr);
}
  
static void log(enum loglevel level, const char *fmt, ...) {
  va_list al;
  va_start(al,fmt);
  vlog(level,fmt,al);
  va_end(al);
}

static void loge(enum loglevel level, const char *msg) {
  int esave= errno;
  log(level,"%s (%d- %s)",msg,esave,strerror(esave));
}

void ohshite(const char *fmt, ...) {
  char buf[500];
  va_list al;
  int esave;

  esave= errno;
  va_start(al,fmt);
  vsprintf(buf,fmt,al);
  va_end(al);
  log(ll_error,"%s (%d- %s)",buf,esave,strerror(esave));
  fprintf(stdout,"484 Server system error: %s (%s)\r\n",buf,strerror(esave));
  exit(0);
}

void ohshit(const char *fmt, ...) {
  va_list al;
  char buf[500];

  va_start(al,fmt);
  vsprintf(buf,fmt,al);
  va_end(al);
  log(ll_error,"%s",buf);
  fprintf(stdout,"484 Server internal error: %s\r\n",buf);
  exit(0);
}

static void ensurelogcmdline(void) {
  if (!*loglinebuf) return;
  log(ll_debug,"<< %s",loglinebuf);
  *loglinebuf=0;
}

static void protocolviolation(const char *string) {
  ensurelogcmdline();
  log(ll_trace,"Protocol violation: %s",string);
  setsupertrace();
  printf("%s\r\n",string);
}

/*
 * Internally used routines
 */

static char *makedatestring(time_t thetime) {
  static char buf[DATESTRING_MAXLEN+5];
  struct tm *tmp;
  tmp= localtime(&thetime);
  if (!strftime(buf,DATESTRING_MAXLEN,DATESTRING_FORMAT,tmp))
    ohshit("Date string too long");
  return buf;
}

static void sigpipehandler(void) {
  log(ll_trace,"Broken pipe, closing");
  fflush(stderr);
  _exit(0);
}

void sigalrmhandler(void);

void settimeout(int fd, int timeout) {
  alarmclosefd= fd;
  signal(SIGALRM,&sigalrmhandler);
}

static void wastimeout(void) {
  log(ll_trace,"timeout, closing");
  fputs("481 Timeout awaiting input - closing connection.\r\n",stdout);
  exit(0);
}

void sigalrmhandler(void) {
  int e, nfd;
  e= errno;
  close(alarmclosefd);
  alarmclosefd= -1;
  nfd= open("/dev/null",O_RDONLY);
  if (nfd >= 0 && nfd != alarmclosefd) {
    dup2(nfd,alarmclosefd);
    close(nfd);
  }
  signal(SIGPIPE,sigpipehandler);
  errno= e;
}

/*
 * Argument parsing
 */

static int noargs(const char *cmd) {
  if (!*cmd) return 1;
  protocolviolation("511 Unexpected or overly-long parameters."); return 0;
}

static void skipspace(char **cmdp) {
  while (**cmdp == ' ') (*cmdp)++;
}

static void id2file(const char *id, char *file) {
  strcpy(file,ITEM_FILENAMEPFX);
  strcat(file,id);
}

static int getalvl(char **cmdp) {
  int c, v;
  char buf[2];
  
  c= **cmdp;
  if (!c) return -1;
  if (!isdigit(c)) goto throw; /* well, we don't have exceptions */
  buf[0]=c; buf[1]=0; v=atoi(buf);
  if (v <= 0 || v > al_max) goto throw;
  c= *++*cmdp;
  if (c && !isspace(c)) goto throw;
  return v;
 throw:
  protocolviolation("511 Requested access level is malformed.");
  return -2;
}

static unsigned long getsequence(void) {
  /* NB the index should already be open and locked at this point,
   * to ensure that sequence numbers are increasing and unique
   */
  FILE *seqfile;
  unsigned long v;

  seqfile= fopen(SEQUENCE_FILENAME,"r+");
  if (!seqfile) ohshite("Failed to open " SEQUENCE_FILENAME);
  errno=0; if (fscanf(seqfile,"%lx",&v) != 1)
    ohshite("Failed to read " SEQUENCE_FILENAME);
  if (fseek(seqfile,0,SEEK_SET) == -1)
    ohshite("Failed to rewind " SEQUENCE_FILENAME);
  if (fprintf(seqfile,"%08lX\n",v+1) == EOF)
    ohshite("Failed to update " SEQUENCE_FILENAME);
  if (fclose(seqfile)) ohshite("Failed to close " SEQUENCE_FILENAME);
  return v;
}

static char *getitemid(char *cmd) {
  int i, c;
  static char buf[ITEMID_LEN+1];
  char *p;

  p= buf;
  if (!isalpha(*cmd)) {
    protocolviolation("511 Item-ID must start with a letter."); return 0;
  }
  *p++= toupper(*cmd); cmd++;
  for (i=1; i<=7; i++) {
    c= *cmd++;
    if (!isdigit(c)) {
      protocolviolation("511 Item-ID must contain 7 digits after the letter."); return 0;
    }
    *p++= c;
  }
  if (*cmd) {
    protocolviolation("511 Garbage after 8 characters of Item-ID."); return 0;
  }
  maycontinue= 0; /* Cancel any pending CONT possibility */
  *p++= 0;
  return buf;
}

static char *newitemid(void) {
  FILE *iaf;
  time_t currenttime;
  long lasttime;
  struct tm *tmp;
  static char buf[ITEMID_LEN+5];

  iaf= fopen(IDARBITER_FILENAME,"r+");
  if (!iaf) ohshite("Failed to open " IDARBITER_FILENAME);
  makelock(iaf,F_WRLCK,IDARBITER_FILENAME);
  currenttime= gettime();
  errno=0; if (fscanf(iaf,"%lx",&lasttime) != 1)
    ohshite("Failed to read " IDARBITER_FILENAME);
  lasttime += 61; /* allow for a leap second just in case */
  if (currenttime < lasttime) currenttime= lasttime;
  rewind(iaf);
  if (fprintf(iaf,"%08lX\n",currenttime) == EOF)
    ohshite("Failed to update " IDARBITER_FILENAME);
  if (ufclose(iaf,IDARBITER_FILENAME)) ohshite("Failed to close " IDARBITER_FILENAME);
  tmp= gmtime(&currenttime);
  if (!tmp) ohshite("Failed to get the Greenwich Mean Time");
  sprintf(buf,"%c%03d%02d%02d",
          'A' + (tmp->tm_year - STARTINGYEAR)%26,
          tmp->tm_yday, tmp->tm_hour, tmp->tm_min);
  return buf;
}

/*
 * Protocol minor components and checks
 */

static void setstatus(int ns, const char *msg) {
  static const char *const statusstrings[]= {
    "no access yet","no posting","posting ok","editor"
  };
  alevel= ns;
  log(ll_trace,"%s (%s)",msg,statusstrings[alevel]);
  printf("23%d %s (%s)\r\n",alevel,msg,statusstrings[alevel]);
}

static void tcpident(void) {
  static int done=0;
  int tcpidents;
  struct sockaddr_in tcpidenta;
  fd_set wfds;
  struct timeval tout;
  char buf[TCPIDENTLINE_MAXLEN+5];
  int flags, nfds, l, i;

  if (done) return;
  done=1;
  tcpidenta= calleraddr;
  tcpidenta.sin_port= htons(TCPPORT_IDENT);
  tcpidents= socket(AF_INET,SOCK_STREAM,0);
  if (tcpidents<0) ohshite("Failed to create Ident socket");
  flags= fcntl(tcpidents,F_GETFL,0);
  if (flags == -1) ohshite("Failed fcntl GETFL on Ident socket");
  flags |= O_NDELAY;
  if (fcntl(tcpidents,F_SETFL,flags)==-1)
    ohshite("Failed fcntl SETFL on Ident socket");
  if (connect(tcpidents,&tcpidenta,sizeof(tcpidenta))) {
    if (errno != EINPROGRESS) {
      int esave= errno;
      log(ll_ident,"Ident connect invalid (%d- %s)",esave,strerror(esave));
      close(tcpidents); return;
    }
    FD_ZERO(&wfds);
    FD_SET(tcpidents,&wfds);
    tout.tv_sec= TCPIDENT_TIMEOUT;
    tout.tv_usec= 0;
    for (;;) {
      nfds= select(tcpidents+1,0,&wfds,0,&tout);  if (nfds != -1) break;
      if (errno != EINTR)
        ohshite("Select failed when waiting for Ident connect");
    }
    if (nfds==0) {
      log(ll_ident,"Ident connect timed out");
      close(tcpidents); return;
    }
    if (connect(tcpidents,&tcpidenta,sizeof(tcpidenta)) && errno != EISCONN) {
      int esave= errno;
      log(ll_ident,"Ident connect failed (%d- %s)",esave,strerror(esave));
      close(tcpidents); return;
    }
  }
  sprintf(buf,"%d, %d\r\n",ntohs(calleraddr.sin_port),port);
  flags &= ~O_NDELAY;
  if (fcntl(tcpidents,F_SETFL,flags)==-1) ohshite("Failed fcntl reset flags");
  signal(SIGPIPE,SIG_IGN);
  errno=0; if (write(tcpidents,buf,strlen(buf)) != strlen(buf))
    ohshite("Writing Ident request");
  signal(SIGPIPE,&sigpipehandler);
  l= 0;
  settimeout(tcpidents,TCPIDENT_TIMEOUT);
  for (;;) {
    i= read(tcpidents,buf+l,sizeof(buf)-l-1);
    if (i==-1) {
      if (errno == EINTR) continue;
      ohshite("Reading Ident reply");
    }
    if (i==0) break;
    l+=i;
  }
  alarm(0);
  close(tcpidents);
  while (l && isspace(buf[l-1])) --l;
  buf[l]= 0;
  log(ll_ident,"Ident response `%s'%s",buf,alarmclosefd==-1 ? " (timed out)" : "");
}

static void setsupertrace(void) {
  if (supertrace) return;
  ensurelogcmdline();
  log(ll_trace,"(Supertrace enabled.)");
  supertrace=1;
}

static int editing(void) {
  if (lenbeforeedit != -1) return 1;
  protocolviolation("500 No EDIT in progress."); return 0;
}

static int datadone(void) {
  if (data) return 1;
  protocolviolation("500 Need DATA first."); return 0;
}

static int noeditinprogress(void) {
  if (lenbeforeedit==-1) return 1;
  protocolviolation("500 EDIT/EDIX still outstanding."); return 0;
}

static void skiptonewline(void) {
  int c;
  while ((c= getchar()) != EOF && c != '\n');
  if (c!=EOF) return;
  if (alarmclosefd == -1) wastimeout();
  if (ferror(stdin)) loge(ll_trace,"Connection died in very long line, closing");
  else log(ll_trace,"EOF during very long line, closing");
  exit(0);
}

static void copyfile(FILE *file, const char *filename) {
  char buf[INPUTLINE_MAXLEN+5];
  int l;

  fputs("250 Data follows\r\n",stdout);
  while (fgets(buf,INPUTLINE_MAXLEN,file)) {
    l= strlen(buf);
    if (!l || buf[l-1] != '\n')
      ohshit("File containing %s is corrupted",filename);
    if (buf[0]=='.') fputc('.',stdout);
    fwrite(buf,1,l-1,stdout);
    fputs("\r\n",stdout);
  }
  if (ferror(file)) ohshite("Error reading %s",filename);
  fputs(".\r\n",stdout);
}
     
static void noitem(const char *id) {
  printf("410 Item %s does not exist or has been archived.\r\n",id);
  return;
}

static void copycontrib(FILE *item, const char *destid) {
  /* copies data to the destination and closes both */
  int c;
  
  while ((c= fgetc(data)) != EOF) {
    if (fputc(c,item)==EOF)
      ohshite("AARGH! Failed to write all of reply to %s", destid);
  }
  if (ferror(data))
    ohshite("AARGH! Failed to read all of reply file for %s",destid);
  fclose(data); data=0;
  if (fclose(item))
    ohshite("AARGH! Failed to close %s after reply",destid);
}

static void indexentry(FILE *index, unsigned long sequence,
                       long timestamp, const char *refid,
                       int type, const char *subject) {
  /* makes an index entry */
  char indexbuf[INDEXENTRY_LENINF+5];
  int l;

  sprintf(indexbuf,"%08lX %08lX",sequence,timestamp);
  memset(indexbuf+17,' ',INDEXENTRY_LENINF-17-1);
  memcpy(indexbuf+18,refid,ITEMID_LEN);
  memcpy(indexbuf+19+ITEMID_LEN,userid,strlen(userid));
  indexbuf[20+ITEMID_LEN+USERID_MAXLEN]= type;

  l= strlen(subject);
  if (l > SUBJECTININDEX_MAXLEN) {
    memcpy(indexbuf+22+ITEMID_LEN+USERID_MAXLEN, subject, SUBJECTININDEX_MAXLEN-3);
    memcpy(indexbuf+22+ITEMID_LEN+USERID_MAXLEN+SUBJECTININDEX_MAXLEN-3, "...", 3);
  } else {
    memcpy(indexbuf+22+ITEMID_LEN+USERID_MAXLEN, subject, l);
  }
  
  indexbuf[INDEXENTRY_LENINF-1]= '\n';
  if (fwrite(indexbuf,INDEXENTRY_LENINF,1,index) != 1)
    ohshite("AARGH! Failed to write index entry relating to %s",refid);
}  

static int line1toolong(const char *p) {
  return (strchr(p,'\n')-p) > TEXTLINE_MAXLEN;
}

static char *createitem(FILE *index, unsigned long sequence,
                        time_t timestamp, const char *subject,
                        int typecodechar, const char *continuing) {
  /* NB the index file must have been locked.  The subject must already have
   * been checked for length */
  FILE *item;
  char *newid, *datestring;
  char idfile[ITEM_MAXFILENAMELEN+5];
  char headbuf[INPUTLINE_MAXLEN*5+5];
  
  newid= newitemid(); id2file(newid,idfile);
  item= fopen(idfile,"w+");
  if (!item) ohshite("File for new item %s uncreateable",newid);

  datestring= makedatestring(timestamp);
  if (!*grogname) {
    sprintf(headbuf, ITEMSTART_PFXSTRING "%s from %s at %s\n",
            newid,userid,datestring);
    if (line1toolong(headbuf))
      sprintf(headbuf,
              ITEMSTART_PFXSTRING "%s submitted at %s by\n"
              LONGUSERID_PFXSTRING "%s\n",
              newid,datestring,userid);
  } else {
    sprintf(headbuf,ITEMSTART_PFXSTRING "%s from %s (%s) at %s\n",
            newid,grogname,userid,datestring);
    if (line1toolong(headbuf))
      sprintf(headbuf,
              ITEMSTART_PFXSTRING "%s from %s at %s\n"
              LONGGROGNAME_PFXSTRING "%s\n",
              newid,userid,datestring,grogname);
    if (line1toolong(headbuf))
      sprintf(headbuf,
              ITEMSTART_PFXSTRING "%s from %s at %s\n"
              LONGUSERID_PFXSTRING "%s\n",
              newid,grogname,datestring,userid);
    if (line1toolong(headbuf))
      sprintf(headbuf,
              ITEMSTART_PFXSTRING "%s submitted at %s\n"
              LONGGROGNAME_PFXSTRING "%s\n"
              LONGUSERID_PFXSTRING "%s\n",
              newid,datestring,grogname,userid);
  }
  if (fprintf(item,
              "%*s %*s          %08lX\n"
              "^%08lX %08lX\n"
              "%s"
              SUBJECT_PFXSTRING "%s\n\n",
              ITEMID_LEN, continuing, ITEMID_LEN, "", sequence,
              sequence, timestamp,
              headbuf, subject) == EOF)
    ohshite("Failed to write item header to %s",newid);
  copycontrib(item,newid);

  indexentry(index, sequence, timestamp, newid, typecodechar, subject);
  printf("120 %s\r\n",newid);
  return newid;
}

static int checknocont(FILE *item, char *id) {
  char statusbuf[ITEMID_LEN*2+21+5];

  if (fseek(item,0,SEEK_SET)) ohshite("Rewind failed for checknocont %s",id);
  if (!fgets(statusbuf,ITEMID_LEN*2+21,item)) {
    if (ferror(item)) ohshite("Item %s status unreadable",id);
    noitem(id); return 0;
  }
  if (strlen(statusbuf) != ITEMID_LEN*2+20 ||
      statusbuf[ITEMID_LEN*2+19] != '\n')
    ohshit("Item %s has corrupted status line",id);
  if (statusbuf[ITEMID_LEN+1] != ' ') {
    printf("122 %*.*s\r\n"
           "422 Item has already been continued.\r\n",
           ITEMID_LEN*2+10,ITEMID_LEN*2+10,statusbuf+ITEMID_LEN+1);
    return 0;
  }
  return 1;
}

static int subjectok(char **cmdp) {
  if (!**cmdp) {
    protocolviolation("511 No Subject line specified for new item."); return 0;
  }
  if (strlen(*cmdp)+sizeof(SUBJECT_PFXSTRING)-1 > TEXTLINE_MAXLEN) {
    fputs("424 Subject is too long.\r\n",stdout);
    return 0;
  }
  return 1;
}

char *getitemsubject(FILE *item, const char **emsg) {
  /* If incorrectly formatted sets *emsg and returns 0. */
  int i;
  static char subjbuf[INPUTLINE_MAXLEN+5];
  char *subjstart;
  int l;

  if (fseek(item,ITEMID_LEN*2+20,SEEK_SET)) {
    *emsg= "fseek for subject failed"; return 0;
  }
  i=0;
  for (;;) {
    if (++i>4) { *emsg= "has no subject (searched first 4 lines)"; return 0; }
    if (fgets(subjbuf,INPUTLINE_MAXLEN,item) ==0) {
      if (ferror(item)) ohshite("Reading file looking for subject");
      *emsg= "has no subject (searched until early EOF)";
      return 0;
    }
    if (!strncmp(subjbuf,SUBJECT_PFXSTRING,sizeof(SUBJECT_PFXSTRING)-1)) break;
  }
  subjstart= subjbuf + sizeof(SUBJECT_PFXSTRING) - 1;
  l= strlen(subjstart);
  while (l && isspace(subjstart[l-1])) l--;
  if (!l) { *emsg= "has empty subject"; return 0; }
  subjstart[l]= 0;
  return subjstart;
}

static int getnewsecret(unsigned char *buf) {
  FILE *file;
  struct stat stab;
  long truncto;
  int bytes= DEFAULT_SECRETBYTES;
  int n;

  file= fopen(RANDOMSTUFF_FILENAME,"r+b");
  if (!file) ohshite("Failed to open " RANDOMSTUFF_FILENAME);
  makelock(file,F_WRLCK,RANDOMSTUFF_FILENAME);
  if (fstat(fileno(file),&stab)) ohshite("Failed to fstat " RANDOMSTUFF_FILENAME);
  truncto= stab.st_size - bytes;
  if (truncto <= RANDOMSTUFF_LOW) {
    fputs("484 I've run out of random numbers - please try tomorrow.\r\n",
          stdout);
    log(ll_error,"Random numbers down to low water, registration rejected");
    exit(0);
  } else if (truncto <= RANDOMSTUFF_WARN) {
    log(ll_error,"Random numbers running low");
  }
  if (fseek(file, truncto, SEEK_SET) == -1) ohshite("Failed to seek for random");
  memset(buf,0,SECRET_MAXBYTES);
  errno=0; n= fread(buf,1,bytes,file);
  if (n != bytes) ohshite("Failed to read random");
  if (ftruncate(fileno(file),truncto)) ohshite("Failed to truncate random");
  if (ufclose(file,RANDOMSTUFF_FILENAME)) ohshite("Failed to close random");
  return bytes;
}

static void regster(void) {
  struct userentry ue;
  FILE *file;
  int rc, i, child, status;
  char sbuf[10];

  log(ll_trace,"Registration requested `%s'",userid); tcpident();

  memcpy(ue.userid, userid, USERID_MAXLEN);
  ue.access= DEFAULT_ACCESS;
  ue.ident= uil_md5initial;
  ue.secretbytes= getnewsecret(ue.secret);
  ue.lastref= gettime();
  ue.disabled= 0;

  rc= userdb_change(USERDB_FILENAME,&ue,2);
  if (rc==1) {
    log(ll_alert,"Re-registration rejected");
    fputs("482 Re-registration denied - contact the editors.\r\n",stdout);
    exit(0);
  } else if (rc==2) {
    log(ll_error,"User database is full!");
    fputs("484 Sorry, user database is full.  Please try again later.\r\n",
          stdout);
    exit(0);
  }

  file= tmpfile(); if (!file) ohshite("Failed to make tmp file for secret");
  for (i=0; i < ue.secretbytes; i++)
    if (fprintf(file, "%02X", ue.secret[i]) == EOF)
      ohshite("Failed to write digits of secret to tmp file");
  if (fflush(file)) ohshite("Failed to flush digits of secret to tmp file");
  if (fseek(file,0,SEEK_SET) == -1) ohshite("Failed to fseek secret tmp file");
  if (lseek(fileno(file),0,SEEK_SET)==-1) ohshite("Failed to lseek secret tmp file ");

  sprintf(sbuf,"%d",ue.access);
  log(ll_alert,"Registration - sending mail ...");

  if ((child= fork()) == -1) ohshite("Fork for reguser");
  if (!child) {
    close(0); errno=0;
    if (dup(fileno(file))) { perror("Failed to dup file to stdin"); _exit(1); }
    execlp(REGUSER_PROGRAM,REGUSER_PROGRAM,userid,sbuf,clientid,(char*)0);
    perror("exec " REGUSER_PROGRAM " failed"); _exit(1);
  }
  if (waitpid(child,&status,0) != child)
    ohshite("Failed to wait for reguser process");
  if (!WIFEXITED(status))
    ohshit("reguser subprocess failed with code %d",status);
  status= WEXITSTATUS(status);
  if (status == 0) {
    log(ll_trace,"reguser subprocess completed successfully");
    exit(0);
  }
  if (status != 11) ohshit("reguser subprocess returned exit status %d",status);
  log(ll_trace,"reguser subprocess gave exit status 11, allowing go-around");

  userid[0]= 0;
}
  
/*
 * Command implementations
 */

struct commandinfo {
  const char *command;
  void (*function)(char*);
  int alevel;
};

/* GCC won't let me declare this static because I don't say
 * how big it is.  How do I simply _declare_ rather than define
 * this array ?
 */
const struct commandinfo commandinfos[];

/*
 * Identification, session management, etc.
 */

static void cmd_dbug(char *cmd) {
  if (!noargs(cmd)) return;
  if (!debugserver) {
    if (!supertrace) {
      log(ll_alert,"Debug requested"); tcpident(); setsupertrace();
      fputs("200 Debug mode enabled.\r\n",stdout);
    } else {
      log(ll_trace,"DBUG reissued; giving `200 Already operative'");
      fputs("200 Debug mode already operative.\r\n",stdout);
    }
  } else {
    if (debuglevel < 9) {
      debuglevel++;
      log(ll_trace,"Entering debug level %d",debuglevel);
      printf("200 Debug level %d.\r\n",debuglevel);
   } else {
      fputs("200 Debug level already at maximum.\r\n",stdout);
    }
  }
}

static void cmd_help(char *cmd) {
  const struct commandinfo *cip;
  int pil;
  
  if (!noargs(cmd)) return;
  log(ll_trace,"HELP requested"); setsupertrace();
  fputs("250 Help information follows ...\r\n"
        " The commands supported by this server are:\r\n",stdout);
  for (pil=0, cip=commandinfos; cip->command; cip++,pil++) {
    if (pil > 4) { fputs("\r\n",stdout); pil=0; }
    printf("    %-10s",cip->command);
  }
  fputs("\r\n",stdout);
  fputs(".\r\n",stdout);
}

static void cmd_quit(char *cmd) {
  if (!noargs(cmd)) return;
  log(ll_trace,"QUIT, closing");
  fputs("280 Goodbye.\r\n",stdout);
  exit(0);
}

static int mustscanhex(char **cmdp, int n, unsigned char *dest) {
  if (scanhex(cmdp,n,dest)) return 1;
  protocolviolation("511 Hex stream contained non-hex-digit or finished too early.");
  return 0;
}

static void md5_sendchal(void) {
  struct timeval timevab;
  unsigned long ul;
  unsigned short us;
  
  if (gettimeofday(&timevab,(void*)0)) ohshite("Failed gettimeofday for nonce");
  memcpy(servernonce,&timevab.tv_sec,4);
  ul= (timevab.tv_usec << 12) + servseq; memcpy(servernonce+4,&ul,4);
  memcpy(servernonce+8,&calleraddr.sin_addr,4);
  memcpy(servernonce+12,&calleraddr.sin_port,2);
  us= getpid(); memcpy(servernonce+14,&us,2);

  if (identue.secretbytes < 0 || identue.secretbytes > SECRET_MAXBYTES)
    ohshit("User database corrupted - secret length out of range");
  
  fputs("333 ",stdout); sendhex(servernonce,16); fputs("\r\n",stdout);
}

static void md5_copyuserid(unsigned char *dest, const char *src) {
  memset(dest,0,16);
  strncpy(dest,src,16);
}

static void authfailure(const char *msg, int twoorthree) {
  /* NB! This function sometimes RETURNS! */
  if (alevel) {
    fprintf(stdout,"43%d %s.\r\n",twoorthree,msg); return;
  } else {
    fprintf(stdout,"48%d %s.\r\n",twoorthree,msg);
    log(ll_trace,"Closing due to auth failure");
    exit(0);
  }
}

static void authorise(const char *userid, int ac) {
  const struct userentry *uep;
  struct userentry ue;

  log(ll_trace,"Requested user `%.50s', access %d", userid, ac);
  if (debuglevel > 0) {
    setstatus(al_edit,"Login successful - debug mode");
    return;
  }
  uep= userdb_find(USERDB_FILENAME,userid,ac);
  if (!uep) {
    if (ac>=0 && (uep= userdb_find(USERDB_FILENAME,userid,-1))) {
      if (uep->access > 0) {
        log(ll_alert,"Wrong access level - can have %d",uep->access);
        tcpident(); authfailure("You are denied that access level",2); return;
      }
    } else {
      log(ll_alert,"Unknown user rejected"); tcpident();
      authfailure("You are unknown to me - please ask the Editors for a userid",2);
      return;
    }
  }
  ue= *uep;  ue.lastref= gettime();  userdb_change(USERDB_FILENAME,&ue,0);
  if (uep->disabled) {
    log(ll_alert,"Disabled user rejected"); tcpident();
    authfailure("That userid is disabled; contact the Editors",2);
    exit(0);
  }
  switch (uep->ident) {
  case uil_none:
    if (uep->access < 0 || uep->access > al_max)
      ohshit("Unknown access level code `%d'",uep->access);
    setstatus(uep->access,"Unconfirmed login OK");
    return;
  case uil_md5initial:
    log(ll_trace,"This user still in `initial' registration state");
  case uil_md5:
    log(ll_trace,"Requested proof of identity");
    fputs("130 MD5  Please provide proof of identity.\r\n",stdout);
    memcpy(&identue, uep, sizeof(identue));
    md5_sendchal();
    return;
  default:
    ohshit("Unknown ident level code `%d'",uep->ident,userid);
  }
}

static void cmd_auth(char *cmd) {
  struct MD5Context md5ctx;
  unsigned char clienthash[16], clientnonce[16], digest[16];
  unsigned char messagebuf[16*3+SECRET_MAXBYTES];
  char *hexp;
  unsigned char *p, *q;
  int i, rc;

  if (!*identue.userid) {
    protocolviolation("500 AUTH not expected."); return;
  }
  hexp= cmd;
  if (!mustscanhex(&cmd,16,clienthash)) return;
  skipspace(&cmd);
  if (!mustscanhex(&cmd,16,clientnonce) || !noargs(cmd)) return;

  if (supertrace) log(ll_debug,"AUTH was `%s'",hexp);

  memcpy(messagebuf,clientnonce,16);
  memcpy(messagebuf+16,servernonce,16);
  md5_copyuserid(messagebuf+32,identue.userid);
  for (p=identue.secret, q=messagebuf+48, i=identue.secretbytes;
       /* We checked the value of identue.secretbytes in md5_sendchal. */
       i>0;
       i--) *q++= ~*p++;
  MD5Init(&md5ctx);
  if (debuglevel > 0) {
    fputs("119 clienthash=MD5(",stdout);
    sendhex(messagebuf,48);
    fprintf(stdout,"!!%d)\r\n",identue.secretbytes);
  }
  MD5Update(&md5ctx,messagebuf,48+identue.secretbytes);
  MD5Final(digest,&md5ctx);
  if (debuglevel > 1) {
    fputs("119 clienthash=",stdout);
    sendhex(digest,16);
    fputs("\r\n",stdout);
  }
  if (memcmp(digest,clienthash,16)) {
    log(ll_alert,"Crypto mismatch - access denied"); tcpident();
    authfailure("Identity confirmation failed",3); *identue.userid=0; return;
  }

  memcpy(messagebuf,servernonce,16);
  memcpy(messagebuf+16,clientnonce,16);
  md5_copyuserid(messagebuf+32,identue.userid);
  memcpy(messagebuf+48,identue.secret,identue.secretbytes);
  MD5Init(&md5ctx);
  if (debuglevel > 0) {
    fputs("119 serverhash=MD5(",stdout);
    sendhex(messagebuf,48);
    fprintf(stdout,"??%d)\r\n",identue.secretbytes);
  }
  MD5Update(&md5ctx,messagebuf,48+identue.secretbytes);
  MD5Final(digest,&md5ctx);
  fputs("133 ",stdout); sendhex(digest,16); fputs("\r\n",stdout);

  if (identue.ident==uil_md5initial) {
    identue.ident= uil_md5;
    rc= userdb_change(USERDB_FILENAME,&identue,0);
    if (rc) ohshit("Change ident level status return %d",rc);
    log(ll_trace,"Registration confirmed by successful login");
    setstatus(identue.access,"Registration complete");
  } else {
    setstatus(identue.access,"Identity confirmed");
  }
  *identue.userid= 0;
}

static void cmd_alvl(char *cmd) {
  int ac;

  ac= getalvl(&cmd); if (ac<-1) return;

  if (!*userid) {
    protocolviolation("500 Need to be logged in using USER to use ALVL."); return;
  }
  if (*identue.userid) {
    protocolviolation("500 Authentication procedure in progress."); return;
  }
  if (ac == -1) {
    fputs("432 Sorry, I don't do default levels.\r\n",stdout);
  } else if (ac < alevel) {
    setstatus(ac,"Access downgraded on request");
  } else if (ac == alevel) {
    fprintf(stdout,"23%d Access level unchanged.\r\n",alevel);
  } else {
    authorise(userid,ac);
  }
}

static void cmd_user(char *cmd) {
  int ac= -1;
  char *p;
  const char *e;
  char violationbuf[512];
  
  p= strchr(cmd,' ');
  if (p) {
    *p++= 0;  skipspace(&p);
    ac= getalvl(&p); if (ac<-1) return;
    skipspace(&p); if (!noargs(p)) return;
  }
  if (*userid) { protocolviolation("500 Already logged in."); return; }
  userid[USERID_MAXLEN]= 0;
  if ((e= userdb_checkid(cmd,userid))) {
    sprintf(violationbuf,"511 Malformed or missing userid (`%.50s', %.200s)", cmd, e);
    protocolviolation(violationbuf); *userid= 0; return;
  }
  if (registration) regster();
  else authorise(userid,ac);
}

static void cmd_regu(char *cmd) {
  if (!noargs(cmd)) return;
  if (userid[0] || registration) {
    protocolviolation("500 REGU not allowed after USER or REGU."); return;
  }

  fputs("100 Processing registration request - please stand by.\r\n",stdout);
  fputs(REGUWARNING_STRING,stdout);
  registration= 1;
  log(ll_alert,"REGU accepted, warning issued"); tcpident();
}

/*
 * Contributions and replies
 */

static void cmd_cont(char *cmd) {
  FILE *olditem, *index;
  char oldidfile[ITEM_MAXFILENAMELEN+5];
  unsigned long sequence;
  time_t currenttime;
  char *newid, *oldsubject;
  const char *emsg;

  if (!datadone() || !subjectok(&cmd) || !noeditinprogress()) return;
  if (!maycontinue) {
    protocolviolation("520 Continuation only allowed after "
                      "an item found to be too full.");
    return;
  }
  index= fopen(INDEX_FILENAME,"a");
  if (!index) ohshite("Index inaccessible for continuation");
  makelock(index,F_WRLCK,INDEX_FILENAME);
  
  id2file(saveditemid,oldidfile);
  olditem= fopen(oldidfile,"r+");
  if (!olditem) {
    if (errno!=ENOENT)
      ohshite("Item %s inaccessible for continuation",saveditemid);
    noitem(saveditemid); ufclose(index,INDEX_FILENAME); return;
  }

  sequence= getsequence();
  currenttime= gettime();
  makelock(olditem,F_WRLCK,oldidfile);
  if (!checknocont(olditem,saveditemid)) {
    ufclose(index,INDEX_FILENAME); ufclose(olditem,oldidfile); return;
  }
  oldsubject= getitemsubject(olditem,&emsg);
  if (!oldsubject) ohshit("Item %s %s",saveditemid,emsg);
  newid= createitem(index,sequence,currenttime,cmd,'C',saveditemid);
  indexentry(index,sequence,currenttime,saveditemid,'F',oldsubject);
  if (ufclose(index,INDEX_FILENAME))
    ohshite("AARGH! Failed to close index after entry about %s",newid);

  if (fseek(olditem,ITEMID_LEN+1,SEEK_SET))
    ohshite("AARGH! Item %s unseekable for recording continuation",saveditemid);
  errno=0;
  if (fwrite(newid,1,ITEMID_LEN,olditem)!=ITEMID_LEN)
    ohshite("AARGH! Item %s unwriteable for recording continuation",saveditemid);
  maycontinue= 0;
  if (fseek(olditem,0,SEEK_END))
    ohshite("AARGH! Item %s unseekable for appending continuationmarker");
  if (fprintf(olditem, "\n^%08lX %08lX\n[Continued in %s by %s.]\n",
              sequence, currenttime, newid, userid) == EOF)
    ohshite("AARGH! Item %s unwriteable for appending continuationmarker",
            saveditemid);

  if (ufclose(olditem,oldidfile))
      ohshite("AARGH! Failed to close item %s after continuing in %s",
             saveditemid,newid);
  printf("220 %08lX  Continuation item inserted and index updated.\r\n",
         sequence);
}

static void cmd_data(char *cmd) {
  char mybuf[INPUTLINE_MAXLEN+5];
  char erbuf[INDEXENTRY_LENINF+100];
  const char *msg;
  const char *formaterror;
  int firstline, l;
  char *linestart;

  if (!(noargs(cmd))) return;
  if (data) fclose(data);
  data= tmpfile();
  if (!data) ohshite("Failed to create temporary file");
  firstline= lenbeforeedit==-1 || saveditemid[0]; *grogname= 0;
  printf("150 Send %s; finish with `.'\r\n",
         lenbeforeedit==-1 ? "grogname and text" :
         saveditemid[0] ? "item status (ignored) and updated contents" :
                          "updated index");
  settimeout(0,DATA_TIMEOUT);
  formaterror= 0;
  for (;;) {
    if (!fgets(mybuf,INPUTLINE_MAXLEN,stdin)) {
      if (alarmclosefd == -1) wastimeout();
      if (ferror(stdin)) { loge(ll_trace,"error reading data, closing"); }
      log(ll_trace,"EOF in data, closing"); exit(0);
    }
    l= strlen(mybuf);
    if (l==0) ohshit("Unexpectedly completely empty line from fgets");
    if (mybuf[--l] != '\n') {
      formaterror= "512 Line in transmitted data is far too long.";
      skiptonewline();
      continue;
    }
    while (l>0 && isspace(mybuf[l-1])) l--;
    if (*mybuf=='.') {
      if (l==1) break;
      if (mybuf[1] != '.') {
        protocolviolation("582 Line starting with `.' wasn't "
                          "dot-doubled or endmarker.");
        log(ll_trace,"Dot-doubling messed up, closing");
        exit(0);
      }
      l--;
      linestart= mybuf+1;
    } else {
      linestart= mybuf;
    }
    if (!formaterror) {
      if (lenbeforeedit!=-1 && !saveditemid[0]) {
        if (l < INDEXENTRY_LENINF-1) {
          memset(linestart+l,' ',INDEXENTRY_LENINF-1-l);
          l= INDEXENTRY_LENINF-1;
        }
        msg=
          l >= INDEXENTRY_LENINF                            ? "line too long"      :
          strspn(linestart,"0123456789ABCDEFabcdef") != 8   ? "gsn format"         :
          linestart[8] != ' '                               ? "space after gsn"    :
          strspn(linestart+9,"0123456789ABCDEFabcdef") != 8 ? "date format"        :
          linestart[17] != ' '                              ? "space after date"   :
          !strchr("RICFEM",linestart[28+USERID_MAXLEN])     ? "RICFEM character"   :
          linestart[27+USERID_MAXLEN] != ' '                ? "space after userid" :
          linestart[29+USERID_MAXLEN] != ' '                ? "space after RICFEM" :
          (linestart[28+USERID_MAXLEN] == 'M' ?
           (strspn(linestart+18," ") < 9                    ? "itemid blank in M"  :
            0 ) :
           (!isalpha(linestart[18])                         ? "itemid letter"      :
            strspn(linestart+19,"0123456789") != 7          ? "itemid digits"      :
            linestart[26] != ' '                            ? "space after itemid" :
            0 ));
        if (msg) {
          linestart[l]= 0;
          sprintf(erbuf,"423 Malformed index entry `%.*s': %s.\r\n",
                  INPUTLINE_MAXLEN-125, linestart, msg);
          formaterror= erbuf;
        }
      } else {/* not a replacement index */
        if (l > TEXTLINE_MAXLEN) {
          l= TEXTLINE_MAXLEN;
          formaterror= "423 Line too long for text of item.\r\n";
        }
      }
    } /* !formaterror */
    linestart[l]= 0;
    if (firstline) {
      if (l + sizeof(LONGGROGNAME_PFXSTRING)-1 > TEXTLINE_MAXLEN) {
        formaterror= "425 Grogname too long.\r\n";
      } else {
        strcpy(grogname,linestart);
      }
      firstline= 0;
    } else if (!formaterror) {
      if (*linestart) {
        if (*linestart=='^' && lenbeforeedit==-1) {
          if (fputc('^',data)==EOF)
            ohshite("Write failed ^-stuff to temp file");
        }
        if (fputs(linestart,data)<0) ohshite("Write failed to temporary file");
      }
      if (fputc('\n',data)==EOF)
        ohshite("Write newline to temporary file failed");
    }
  }
  alarm(0); if (alarmclosefd == -1) wastimeout();
  if (formaterror) {
    if (formaterror[0] == '5') {
      protocolviolation(formaterror);
    } else {
      fputs(formaterror,stdout);
    }
    fclose(data);
    data= 0;
  } else {
    if (fflush(data)) ohshite("Flushing data to temporary file");
    rewind(data);
    if (fstat(fileno(data),&dstab) <0)
      ohshite("Reply temporary file unstattable");
    if (lenbeforeedit==-1 && dstab.st_size > CONTRIB_MAXLEN) {
      fputs("423 Data is too long for a Reply or Contribution.\r\n",stdout);
      fclose(data); data=0;
      return;
    }
    fputs("350 Data received, thanks.  What shall I do with it?\r\n",stdout);
  }
}

static void cmd_newi(char *cmd) {
  FILE *index;
  char *newid;
  unsigned long sequence;
  time_t currenttime;

  if (!noeditinprogress() || !datadone() || !subjectok(&cmd)) return;
    
  maycontinue= 0; /* Cancel any pending CONT possibility */
  index= fopen(INDEX_FILENAME,"a");
  if (!index) ohshite("Index inaccessible for reply append");
  makelock(index,F_WRLCK,INDEX_FILENAME);
  sequence= getsequence();
  currenttime= gettime();
  newid= createitem(index, sequence, currenttime, cmd, 'I', "");
  if (ufclose(index,INDEX_FILENAME))
    ohshite("AARGH! Failed to close index after entry about %s",newid);
  printf("220 %08lX  Item inserted and index updated.\r\n",sequence);
}

static void cmd_repl(char *cmd) {
  FILE *item,*index;
  struct stat istab;
  char *datestring, *id;
  char idfile[ITEM_MAXFILENAMELEN+5];
  char headbuf[USERID_MAXLEN+INPUTLINE_MAXLEN+TEXTLINE_MAXLEN+5];
  char *subjstart;
  const char *emsg;
  unsigned long sequence;
  time_t currenttime;

  if (!noeditinprogress() || !datadone() || !(id=getitemid(cmd))) return;

  if (dstab.st_size > REPLY_MAXLEN) {
    fputs("423 Data is too long for a Reply.\r\n",stdout);
    fclose(data); data=0;
    return;
  }
  
  maycontinue= 0; /* Cancel any pending CONT possibility */
  index= fopen(INDEX_FILENAME,"a");
  if (!index) ohshite("Index inaccessible for reply append");
  makelock(index,F_WRLCK,INDEX_FILENAME);

  id2file(id,idfile);
  item= fopen(idfile,"r+");
  if (!item) {
    if (errno!=ENOENT) ohshite("Item %s inaccessible for reply",id);
    noitem(id); ufclose(index,INDEX_FILENAME); return;
  }
  makelock(item,F_WRLCK,idfile);

  if (!checknocont(item,id)) {
    ufclose(index,INDEX_FILENAME); ufclose(item,idfile); return;
  }
  if (fstat(fileno(item),&istab) <0)
    ohshite("Item %s unstattable for reply",id);
  if (istab.st_size + dstab.st_size > ITEM_MAXLEN) {
    fputs("421 Reply is too long to fit in the same item.\r\n",stdout);
    strcpy(saveditemid,id); maycontinue= 1;
    ufclose(index,INDEX_FILENAME); ufclose(item,idfile); return;
  }
  sequence= getsequence();
  currenttime= gettime();
  subjstart= getitemsubject(item,&emsg);
  if (!subjstart) ohshit("Item %s %s",id,emsg);
  if (fseek(item,ITEMID_LEN*2+11,SEEK_SET))
    ohshite("Item %s unseekable for recording reply sequence",id);
  if (fprintf(item,"%08lX",sequence) == EOF)
    ohshite("AARGH! Item %s recording reply sequence failed",id);
  if (fseek(item,0,SEEK_END)) ohshite("AARGH! Item %s unseekable to end",id);

  datestring= makedatestring(currenttime);
  if (!*grogname) {
    sprintf(headbuf,REPLYSTART_PFXSTRING "from %s at %s\n",userid,datestring);
    if (line1toolong(headbuf))
      sprintf(headbuf,
              REPLYSTART_PFXSTRING "submitted at %s by\n"
              LONGUSERID_PFXSTRING "%s\n",
              datestring,userid);
  } else {
    sprintf(headbuf,REPLYSTART_PFXSTRING "from %s (%s) at %s\n",
            grogname,userid,datestring);
    if (line1toolong(headbuf))
      sprintf(headbuf,
              REPLYSTART_PFXSTRING "from %s at %s\n"
              LONGGROGNAME_PFXSTRING "%s\n",
              userid,datestring,grogname);
    if (line1toolong(headbuf))
      sprintf(headbuf,
              REPLYSTART_PFXSTRING "from %s at %s\n"
              LONGUSERID_PFXSTRING "%s\n",
              grogname,datestring,userid);
    if (line1toolong(headbuf))
      sprintf(headbuf,
              REPLYSTART_PFXSTRING "submitted at %s\n"
              LONGGROGNAME_PFXSTRING "%s\n"
              LONGUSERID_PFXSTRING "%s\n",
              datestring,grogname,userid);
  }
  if (fprintf(item,"\n^%08lX %08lX\n%s\n",sequence,currenttime,headbuf) == EOF)
    ohshite("AARGH! Failed to write reply header to %s",id);
  copycontrib(item,id);
  unlock(item,idfile);
  
  indexentry(index, sequence, currenttime, id, 'R', subjstart);
  if (ufclose(index,INDEX_FILENAME))
    ohshite("AARGH! Failed to close index after reply to %s",id);
  printf("220 %08lX  Reply to %s inserted and index updated.\r\n",sequence,id);
}

/*
 * Retreival
 */

static void cmd_elog(char *cmd) {
  FILE *elog;

  if (!noargs(cmd)) return;
  elog= fopen(EDITLOG_FILENAME,"r");
  if (!elog) {
    if (errno==ENOENT) {
      fputs("250 No edits stored\r\n.\r\n",stdout); return;
    }
    ohshite("Edit log `" EDITLOG_FILENAME "' inaccessible");
  }
  copyfile(elog,EDITLOG_FILENAME);
  fclose(elog);
}

static void cmd_indx(char *cmd) {
  FILE *index;
  long datefrom,here;
  int min,max,try,useseq=0;
  struct stat stab;
  char buf[INDEXENTRY_LENINF+5];
  char *estr;

  if (*cmd == '#') { cmd++; useseq=1; }
  if (*cmd) {
    datefrom= strtol(cmd,&estr,16);
    if (*estr) { protocolviolation("511 Date must be only a hex number."); return; }
  } else {
    datefrom= 0;
  }
  index= fopen(INDEX_FILENAME,"r"); if (!index) ohshite("Index inaccessible");
  makelock(index,F_RDLCK,INDEX_FILENAME);
  if (fstat(fileno(index),&stab)) ohshite("Index unstattable");
  if (stab.st_size % INDEXENTRY_LENINF)
    ohshit("Index corrupt - invalid length %d",stab.st_size);
  min=0; max= stab.st_size / INDEXENTRY_LENINF;
  if (debuglevel > 2)
    printf("119  min=%-2d  max=%-2d          want=%08lx\r\n",min,max,datefrom);
  while (min < max) {
    try= (min+max)>>1;
    if (fseek(index,try*INDEXENTRY_LENINF,SEEK_SET))
      ohshite("Index unseekable during search %d",try);
    if (fread(buf,INDEXENTRY_LENINF,1,index) != 1)
      ohshite("Index unreadable during search");
    here= strtol(useseq ? buf : buf+9, &estr, 16);
    if (debuglevel > 2)
      printf("119  min=%-2d  max=%-2d  try=%-2d  here=%08lx\r\n",
             min, max, try, here);
    if (*estr != ' ') ohshit("Index has corrupted record %d",try);
    if (here >= datefrom) { max=try; } else { min=try+1; }
  }
  if (debuglevel > 2)
    printf("119  min=%-2d  max=%-2d\r\n",min,max);
  if (fseek(index,min*INDEXENTRY_LENINF,SEEK_SET)) ohshite("Index unseekable");
  copyfile(index,INDEX_FILENAME);
  ufclose(index,INDEX_FILENAME);
}

static void cmd_motd(char *cmd) {
  FILE *motd;

  if (!noargs(cmd)) return;
  motd= fopen(MOTD_FILENAME,"r");
  if (!motd) {
    if (errno!=ENOENT) ohshite("Message of the Day inaccessible");
    printf("410 There is no message of the day.\r\n");
    return;
  }
  makelock(motd,F_RDLCK,MOTD_FILENAME);
  copyfile(motd,MOTD_FILENAME);
  ufclose(motd,MOTD_FILENAME);
}

static void cmd_item(char *cmd) {
  FILE *item;
  char idfile[ITEM_MAXFILENAMELEN+5], *id;

  if (!(id=getitemid(cmd))) return;
  id2file(id,idfile);
  item= fopen(idfile,"r");
  if (!item) {
    if (errno!=ENOENT) ohshite("Item %s inaccessible",id);
    noitem(id); return;
  }
  makelock(item,F_RDLCK,idfile);
  copyfile(item,id);
  ufclose(item,idfile);
}

static void cmd_diff(char *cmd) {
  FILE *file, *diff;
  char *id;
  char filename[ITEM_MAXFILENAMELEN+5];
  char filename2[ITEM_MAXFILENAMELEN+sizeof(EDITED_FILENAMESFX)+5];

  if (*cmd) {
    if (!(id=getitemid(cmd))) return;
    id2file(id,filename);
  } else {
    strcpy(filename,INDEX_FILENAME);
    id= 0;
  }
  strcpy(filename2,filename);
  strcat(filename2,EDITED_FILENAMESFX);
  
  file= fopen(filename,"r");
  if (file) {
    makelock(file,F_RDLCK,filename);
  } else if (errno!=ENOENT) {
    ohshite("Item/index file %s inaccessible",filename);
  }

  diff= fopen(filename2,"r");
  if (!diff) {
    if (errno!=ENOENT) ohshite("Diff file %s inaccessible",filename2);
    fputs("410 There are no relevant diffs.\r\n",stdout); ufclose(file,filename);
  } else {
    copyfile(diff,filename2);
    fclose(diff);
  }
  if (file) ufclose(file,filename);
}

static void cmd_stat(char *cmd) {
  FILE *item;
  char idfile[ITEM_MAXFILENAMELEN+5], *id;
  char statusbuf[ITEMID_LEN*2+21+5];
  char *subjstart;
  const char *emsg;
  
  if (!(id=getitemid(cmd))) return;
  maycontinue= 0; /* Cancel any pending CONT possibility */
  id2file(id,idfile);
  item= fopen(idfile,"r");
  if (!item) {
    if (errno!=ENOENT) ohshite("Item %s inaccessible",id);
    noitem(id); return;
  }
  makelock(item,F_RDLCK,idfile);
  if (!fgets(statusbuf,ITEMID_LEN*2+21,item)) {
    if (ferror(item)) ohshite("Item %s status unreadable",id);
    noitem(id); return;
  }
  if (strlen(statusbuf) != ITEMID_LEN*2+20 ||
      statusbuf[ITEMID_LEN*2+19] != '\n')
    ohshit("Item %s has corrupted status line",id);
  statusbuf[ITEMID_LEN*2+19]= 0;
  subjstart= getitemsubject(item,&emsg);
  if (!subjstart) ohshit("Item %s %s",id,emsg);
  ufclose(item,idfile);
  printf("211 %s %s\r\n",statusbuf,subjstart);
}

/*
 * Editing
 */

static void cmd_edlk(char *cmd) {
  struct flock fl;
  char uidbuf[USERID_MAXLEN+1];
  
  if (!noargs(cmd)) return;
  if (edit) { protocolviolation("500 EDLK already issued."); return; }
  
  edit= fopen(EDITLOCK_FILENAME,"r+");
  if (!edit) ohshite("Edit lockfile `" EDITLOCK_FILENAME "' inaccessible");
  
  fl.l_type= F_WRLCK;
  fl.l_whence= SEEK_SET;
  fl.l_start= 0;
  fl.l_len= USERID_MAXLEN;
  if (fcntl(fileno(edit),F_SETLK,&fl) == -1) {
    if (errno == EACCES || errno == EAGAIN) {
      errno=0; if (fread(uidbuf,1,USERID_MAXLEN,edit) != USERID_MAXLEN)
        ohshite("Failed to read userid of locking editor from "
                EDITLOCK_FILENAME);
      fclose(edit); edit=0; uidbuf[USERID_MAXLEN]=0;
      printf("411 %s has locked the message area for editing\r\n",uidbuf);
      return;
    }
    ohshite("Failed to lock " EDITLOCK_FILENAME);
  }
  errno=0; if (fwrite(userid,1,USERID_MAXLEN,edit) != USERID_MAXLEN)
    ohshite("Failed to write own userid to " EDITLOCK_FILENAME);
  if (fflush(edit)) ohshite("Failed to flush userid into edit flag file");
  fputs("200 Message area is now locked for editing.\r\n",stdout);
}

static void cmd_edul(char *cmd) {
  if (!noargs(cmd) || !noeditinprogress()) return;
  if (!edit) { protocolviolation("532 No lock held so can't unlock it."); return; }
  
  rewind(edit);
  errno=0; if (fwrite("??",1,3,edit)!=3)
    ohshite("Failed to erase own userid from " EDITLOCK_FILENAME);
  if (fclose(edit))
    ohshite("Failed to close " EDITLOCK_FILENAME " after erasing my userid");
  edit=0;
  fputs("200 Lock on edit area relinquished.\r\n",stdout);
}

static void startedit(char *id) {
  FILE *file;
  char idfile[ITEM_MAXFILENAMELEN+5];
  const char *filename;
  struct stat istab;

  if (!noeditinprogress()) return;
  if (!edit) { protocolviolation("532 EDLK required before EDIT/EDIX."); return; }
  maycontinue= 0; /* Cancel any pending CONT possibility */

  if (id) {
    id2file(id,idfile); filename= idfile;
  } else {
    filename= INDEX_FILENAME;
  }
  file= fopen(filename,"r");
  if (!file) {
    if (errno!=ENOENT) ohshite("%s inaccessible",filename);
    noitem(id); return;
  }
  makelock(file,F_RDLCK,filename);
  if (fstat(fileno(file),&istab))
    ohshite("%s unstattable before edit",filename);
  lenbeforeedit= istab.st_size;
  copyfile(file,filename);
  ufclose(file,filename);

  log(ll_trace,"Editing %s",filename);

  if (data) { fclose(data); data=0; }
  if (id) { strcpy(saveditemid,id); } else { saveditemid[0]= 0; }
}

static void cmd_edit(char *cmd) {
  char *id;

  if (!(id=getitemid(cmd))) return;
  startedit(id);
}

static void cmd_edix(char *cmd) {
  if (!noargs(cmd)) return;
  startedit(0);
}

static void cmd_edab(char *cmd) {
  if (!noargs(cmd) || !editing()) return;
  if (data) { fclose(data); data=0; }
  lenbeforeedit= -1;
  fputs("200 Edit operation aborted.\r\n",stdout);
}

static void run_diff(const char *itemid_or_index,
                     const char *edited_or_withdrawn,
                     unsigned long sequence,
                     time_t currenttime,
                     const char *datestring,
                     const char *filename1_also_destbasename,
                     const char *newbuf,
                     long newlen) {
  char label1[ITEMID_LEN+50], label2[ITEMID_LEN+DATESTRING_MAXLEN+50];
  char destname[ITEM_MAXFILENAMELEN + sizeof(EDITED_FILENAMESFX) + 50];
  FILE *f1, *dest, *diff;
  int fdi[2];
  int child, status;

  sprintf(label1, "--label=%s Before %08lX %08lX",
          itemid_or_index, sequence, currenttime);
  sprintf(label2, "--label=%s %s at %s",
          itemid_or_index, edited_or_withdrawn, datestring);
  strcpy(destname,filename1_also_destbasename);
  strcat(destname,EDITED_FILENAMESFX);
  
  f1= fopen(filename1_also_destbasename,"r");
  if (!f1) ohshite("Failed to reopen %s for diff",filename1_also_destbasename);
  dest= fopen(destname,"a");
  if (!dest) ohshite("Failed to append to %s for diff",destname);

  if (newlen) {
    if (pipe(fdi)) ohshite("Failed to create pipe for diff of %s",itemid_or_index);
  } else {
    fdi[0]= open("/dev/null",O_RDONLY);
    if (fdi[0] == -1) ohshite("Failed to open /dev/null for diff of %s",itemid_or_index);
  }
    
  if ((child= fork()) == -1) ohshite("Fork for diff of %s",itemid_or_index);
  if (!child) {
    if (dup2(fdi[0],0)) { perror("dup2 for diff stdin failed"); _exit(3); }
    if (dup2(fileno(dest),1) != 1) { perror("dup2 for diff stdout failed"); _exit(3); }
    close(fdi[0]); if (newlen) close(fdi[1]);
    execlp(GNUDIFF_PROGRAM,
           "diff","--text","--unified",label1,label2,
           filename1_also_destbasename,"-",(char*)0);
    perror("exec " GNUDIFF_PROGRAM " failed"); _exit(3);
  }
  close(fdi[0]);
  fclose(dest);
  fclose(f1);
  
  if (newlen) {
    diff= fdopen(fdi[1],"w");
    if (!diff) ohshite("Failed to fdopen diff pipe");
    if (fwrite(newbuf,1,newlen,diff)!=newlen)
      ohshite("Failed to write to pipe to diff of %s",itemid_or_index);
    if (fclose(diff))
      ohshite("Failed to close pipe to diff of %s",itemid_or_index);
    close(fdi[1]);
  }
  if (waitpid(child,&status,0) != child)
    ohshite("Failed to wait for diff of %s",itemid_or_index);
  if (!WIFEXITED(status))
    ohshit("diff of %s gave error wait code %d",itemid_or_index,status);
  status= WEXITSTATUS(status);
  if (status==0 || status==1) return;
  ohshit("diff of %s gave error exit status %d",itemid_or_index,status);
}

static void edcf_item(char *itemid, const char *reason) {
  /* editing, rather than withdrawing */
  FILE *index, *elog, *item;
  const char *datestring;
  const char *emsg;
  unsigned long sequence;
  time_t currenttime;
  char idfile[ITEM_MAXFILENAMELEN+5];
  char *subject;
  struct stat istab;
  long newlen;
  char *newbuf;

  index= fopen(INDEX_FILENAME,"a");
  if (!index) ohshite("Index inaccessible for item edit entry");
  makelock(index,F_WRLCK,INDEX_FILENAME);
  sequence= getsequence();
  currenttime= gettime();
  id2file(itemid,idfile);
  datestring= makedatestring(currenttime);

  item= fopen(idfile,"r+");
  if (!item) {
    if (errno!=ENOENT || !saveditemid[0])
      ohshite("Failed to open %s for edit",idfile);
    noitem(itemid); fclose(data); data=0; lenbeforeedit=-1; ufclose(index,INDEX_FILENAME); return;
  }
  subject= getitemsubject(data,&emsg);
  if (!subject) {
    fputs("423 Subject line missing from edited version.\r\n",stdout);
    fclose(item); ufclose(index,INDEX_FILENAME); fclose(data); data=0; return;
  }
  if (fseek(data,0,SEEK_SET)) ohshite("Rewind data during %s EDCF",itemid);
  
  elog= fopen(EDITLOG_FILENAME,"a");
  if (!elog) ohshite("Failed to open " EDITLOG_FILENAME " re item %s",itemid);

  if (fprintf(elog, "Item %s edited by %s at %s (#%08lX):\n%s\n\n",
              saveditemid,userid,datestring,sequence,reason)
      ==EOF) ohshite("Failed to write to " EDITLOG_FILENAME);
  if (fclose(elog))
    ohshite("Failed to close " EDITLOG_FILENAME " after write");
  
  makelock(item,F_WRLCK,idfile);
  if (fstat(fileno(item),&istab)) ohshite("Failed to stat %s for EDCF",idfile);
  if (lenbeforeedit > istab.st_size)
    ohshit("Item %s has shrunk since EDIT",itemid);

  newlen= istab.st_size - lenbeforeedit + dstab.st_size+ITEMID_LEN*2+20;
  newbuf= malloc(newlen);
  if (!newbuf) ohshite("No memory to contruct edited version");
  errno=0; if (fread(newbuf,1,ITEMID_LEN*2+20,item) != ITEMID_LEN*2+20)
    ohshite("Failed to read status line of %s for EDCF",saveditemid);
  if (newbuf[ITEMID_LEN]!=' ' || newbuf[ITEMID_LEN*2+19]!='\n')
    ohshit("Status line of %s corrupt before EDCF",saveditemid);
  sprintf(newbuf+ITEMID_LEN*2+2,"%08lX",sequence);
  newbuf[ITEMID_LEN*2+10]= ' '; /* undo the null from sprintf */
  errno=0;
  if (fread(newbuf+ITEMID_LEN*2+20,1,dstab.st_size,data) != dstab.st_size)
    ohshite("Failed to block read data during EDCF of %s",itemid);

  if (lenbeforeedit < istab.st_size) {
    if (fseek(item,lenbeforeedit,SEEK_SET))
      ohshite("Seek to new data during EDCF of item %s",item);
    errno= 0;
    if (fread(newbuf + dstab.st_size+ITEMID_LEN*2+20, 1, istab.st_size -
              lenbeforeedit, item) != istab.st_size - lenbeforeedit)
      ohshite("Read new data during EDCF of item %s",itemid);
  }

  run_diff(itemid,"Edited",sequence,currenttime,datestring,
           idfile,newbuf,newlen);

  if (fseek(item,0,SEEK_SET)) ohshite("Rewind %s for write edited",itemid);
  if (fwrite(newbuf,1,newlen,item)!=newlen)
    ohshite("AARGH! Failed to write edited version of %s",itemid);
  if (ftruncate(fileno(item),newlen))
    ohshite("AARGH! Failed to trunctate %s to correct length after edit",
            itemid);
  if (ufclose(item,idfile)) ohshite("AARGH! Failed to close %s after edit",itemid);
  indexentry(index, sequence, currenttime, itemid, 'E', subject);
  if (ufclose(index,INDEX_FILENAME))
    ohshite("AARGH! Failed to close index after edit of %s",itemid);
  fclose(data); data=0; lenbeforeedit=-1; free(newbuf);
  printf("220 %08lX  Edit complete.\r\n",sequence);
}
  
static void edcf_index(const char *reason) {
  /* editing the index */
  FILE *index, *elog;
  const char *datestring;
  time_t currenttime;
  unsigned long sequence;
  long newlen;
  char *newbuf;
  struct stat istab;
  
  index= fopen(INDEX_FILENAME,"r+");
  if (!index) ohshite("Failed to open index for EDCF of index edit");
  makelock(index,F_WRLCK,INDEX_FILENAME);
  sequence= getsequence();
  currenttime= gettime();
  datestring= makedatestring(currenttime);

  elog= fopen(EDITLOG_FILENAME,"a");
  if (!elog) ohshite("Failed to open " EDITLOG_FILENAME " re index edit");
  if (fprintf(elog, "Index edited by %s at %s (#%08lX):\n%s\n\n",
              userid,datestring,sequence,reason) ==EOF)
    ohshite("Failed to write to " EDITLOG_FILENAME);
  if (fclose(elog))
    ohshite("Failed to close " EDITLOG_FILENAME " after write");
    
  if (fstat(fileno(index),&istab)) ohshite("Failed to stat index for EDCF");
  if (lenbeforeedit > istab.st_size) ohshit("Index has shrunk since EDIX");

  newlen= istab.st_size - lenbeforeedit + dstab.st_size;
  newbuf= malloc(newlen);
  if (!newbuf) ohshite("No memory to contruct edited version");
  errno=0; if (fread(newbuf, 1, dstab.st_size, data) != dstab.st_size)
    ohshite("Failed to block read data during EDCF of index");

  if (lenbeforeedit < istab.st_size) {
    if (fseek(index, lenbeforeedit, SEEK_SET))
      ohshite("Seek to new data during EDCF of index");
    errno= 0;
    if (fread(newbuf + dstab.st_size, 1, istab.st_size - lenbeforeedit, index)
        != istab.st_size - lenbeforeedit)
      ohshite("Read new data during EDCF of index");
  }

  run_diff("index","Edited",sequence,currenttime,datestring,
           INDEX_FILENAME,newbuf,newlen);

  if (fseek(index,0,SEEK_SET)) ohshite("Rewind index for write edited");
  if (fwrite(newbuf, 1, newlen, index) != newlen)
    ohshite("AARGH! Failed to write edited version of index");
  if (ftruncate(fileno(index),newlen))
    ohshite("AARGH! Failed to trunctate index to correct length after edit");
  if (ufclose(index,INDEX_FILENAME)) ohshite("AARGH! Failed to close index after edit");
  fclose(data); data=0; lenbeforeedit=-1; free(newbuf);
  printf("220 %08lX  Edit complete.\r\n",sequence);
}

static void edcf_withdraw(char *itemid, const char *reason) {
  char idfile[ITEM_MAXFILENAMELEN+5];
  struct stat istab;
  unsigned long sequence;
  int n, i, j;
  time_t currenttime;
  char *newbuf, *datestring;
  FILE *index, *elog;
  
  index= fopen(INDEX_FILENAME,"r+");
  if (!index) ohshite("Failed to open index to withdraw item %s",itemid);
  makelock(index,F_WRLCK,INDEX_FILENAME);
  sequence= getsequence();
  currenttime= gettime();
  id2file(itemid,idfile);
  datestring= makedatestring(currenttime);

  elog= fopen(EDITLOG_FILENAME,"a");
  if (!elog) ohshite("Failed to open " EDITLOG_FILENAME " re withdrawal");
  if (fprintf(elog, "Item %s withdrawn by %s at %s (#%08lX):\n%s\n\n",
              itemid,userid,datestring,sequence,reason) ==EOF)
    ohshite("Failed to write to " EDITLOG_FILENAME);
  if (fclose(elog))
    ohshite("Failed to close " EDITLOG_FILENAME " after write");
    
  if (fstat(fileno(index),&istab))
    ohshite("Failed to stat index for withdrawal");
  if (istab.st_size % INDEXENTRY_LENINF)
    ohshit("Index found corrupted before withdrawal (length=%ld)",
           (long)istab.st_size);
  newbuf= malloc(istab.st_size);
  if (!newbuf)
    ohshite("No memory to construct changed index for withdrawal");
  
  n= istab.st_size / INDEXENTRY_LENINF;
  errno=0; if (fread(newbuf,INDEXENTRY_LENINF,n,index)!=n)
    ohshite("Failed to read index during withdrawal");
  for (i=0, j=0; i<n; i++) {
    if (!memcmp(newbuf+i*INDEXENTRY_LENINF+18,saveditemid,ITEMID_LEN)) continue;
    if (i != j)
      memcpy(newbuf+j*INDEXENTRY_LENINF,newbuf+i*INDEXENTRY_LENINF,INDEXENTRY_LENINF);
    j++;
  }
  run_diff(itemid,"Withdrawn",sequence,currenttime,datestring,
           INDEX_FILENAME, newbuf,j*INDEXENTRY_LENINF);
  run_diff(itemid,"Withdrawn",sequence,currenttime,datestring,
           idfile, 0,0);

  if (fseek(index,0,SEEK_SET)) ohshite("Rewind index for write withdrawn");
  if (fwrite(newbuf,INDEXENTRY_LENINF,j,index)!=j)
    ohshite("AARGH! Failed to write updated index for withdrawal of %s",
            saveditemid);
  if (ftruncate(fileno(index),j*INDEXENTRY_LENINF))
    ohshite("AARGH! Failed to trunctate index after withdrawal of %s",
            saveditemid);
  if (ufclose(index,INDEX_FILENAME))
    ohshite("AARGH! Failed to close index after withdrawal of %s",saveditemid);
  free(newbuf);

  if (unlink(idfile)) ohshite("Failed to remove withdrawn item %s",idfile);
  lenbeforeedit=-1;
  printf("220 %08lX  Item withdrawn.\r\n",sequence);
}

static void cmd_edcf(char *cmd) {
  if (!*cmd) {
    protocolviolation("511 A reason must be given for the edit."); return;
  }
  if (!editing()) return;
  if (saveditemid[0]) {
    if (data)
      edcf_item(saveditemid,cmd);
    else
      edcf_withdraw(saveditemid,cmd);
  } else {
    if (!data) { protocolviolation("500 Cannot withdraw the index."); return; }
    edcf_index(cmd);
  }
}

/*
 * Management
 */

static void cmd_udbm(char *cmd) {
  const char *args[UDBM_MAXARGS+1];
  int nargs=0;
  int fdi[2];
  int child;
  int status, c;
  char *tosend=0, *p;

  log(ll_trace,"UDBM `%s'",cmd);
  args[nargs++]= "UDBM";
  args[nargs++]= "--file";
  args[nargs++]= USERDB_FILENAME;
  args[nargs++]= "--restrict";
  args[nargs++]= "--noprompt";
  for (;;) {
    skipspace(&cmd);
    if (!*cmd) break;
    if (*cmd == '<') { *cmd++=0; tosend= cmd; break; }
    if (nargs == UDBM_MAXARGS) {
      fputs("250 Too many arguments to UDBM.\r\n"
            "Too many arguments to UDBM.\r\n.\r\n", stdout); return;
    }
    if (*cmd == '"') {
      p= ++cmd;
      args[nargs++]= cmd;
      while ((c= *cmd) && c != '"') {
        if (c == '\\' && cmd[1]) c= *++cmd;
        *p++= c; cmd++;
      }
      *p= 0;
    } else {
      args[nargs++]= cmd;
      while ((c= *cmd) && !isspace(c)) cmd++;
      *cmd= 0;
    }
    if (c) cmd++;
  }
  args[nargs]= 0;
  if (pipe(fdi)) ohshite("Create pipe for stdin for UDBM");
  if ((child= fork()) == -1) ohshite("Fork for UDBM");
  if (!child) {
    fputs("250 Response follows.\r\n",stdout);
    close(0); dup(fdi[0]); close(2); dup(1); close(fdi[0]); close(fdi[1]);
    execvp(UDBM_PROGRAM, (char**)args);
    perror("exec " UDBM_PROGRAM " failed"); _exit(1);
  }
  if (tosend) {
    int l;
    l= strlen(tosend); tosend[l++]= '\n';
    write(fdi[1],tosend,l);
  }
  close(fdi[0]); close(fdi[1]);
  if (waitpid(child,&status,0) != child) ohshite("Failed to wait for udbm subprocess");
  if (WIFSIGNALED(status)) {
    printf("(udbm subprocess died due to receiving signal %d!%s)\r\n",
           WTERMSIG(status), WCOREDUMP(status) ? "  Core dumped!" : "");
  } else if (!WIFEXITED(status)) {
    printf("(udbm subprocess failed, `wait' code %d)\r\n",status);
  } else if (WEXITSTATUS(status)) {
    printf("(udbm subprocess exited with status %d)\r\n",WEXITSTATUS(status));
  }    
  fputs(".\r\n",stdout);
  return;
}

static void sendparent(char *cmd, int sig) {
  pid_t pid;
  if (!noargs(cmd)) return;
  log(ll_alert,"KILL/KILR (signal %d) issued and accepted",sig); tcpident();
  pid= getppid();  if (pid==-1) ohshite("Failed to getppid");
  if (kill(pid,sig))
    ohshite("Failed to send signal %d to parent process (pid %ld)",
            sig, (long)pid);
  fputs("200 KILL/KILR command obeyed.\r\n",stdout);
}

void cmd_kill(char *cmd) { sendparent(cmd,SIGTERM); }
void cmd_kilr(char *cmd) { sendparent(cmd,SIGUSR2); }

static void cmd_mots(char *cmd) {
  FILE *motd, *index;
  unsigned long sequence;
  time_t currenttime;
  static char nullsubject[]="";

  if (!noargs(cmd) || !datadone()) return;

  index= fopen(INDEX_FILENAME,"a");
  makelock(index,F_WRLCK,INDEX_FILENAME);
  currenttime= gettime();
  sequence= getsequence();
  
  motd= fopen(MOTD_FILENAME,"a+");
  makelock(motd,F_WRLCK,MOTD_FILENAME);

  rewind(motd);
  if (ftruncate(fileno(motd),0))
    ohshite("AARGH! Failed to trunctate motd before replace");

  if (fprintf(motd, "%08lX %08lX\n", currenttime, sequence) ==EOF)
    ohshite("Failed to write to " EDITLOG_FILENAME);
  copycontrib(motd,"motd");
  unlock(motd,MOTD_FILENAME);

  indexentry(index,sequence,currenttime, "        ", 'M', nullsubject);
  if (ufclose(index,INDEX_FILENAME)) ohshite("AARGH! Failed to close index after motd update");
  printf("220 %08lX  Message of the Day updated.\r\n",sequence);
}

void cmd_noop(char *cmd) {
  if (!noargs(cmd)) return;
  fputs("200 NOOP command received.\r\n",stdout);
}

/*
 * Command table and main program
 */

const struct commandinfo commandinfos[]= {
  { "AUTH", cmd_auth, al_none  },
  { "ALVL", cmd_alvl, al_none  },
  { "DBUG", cmd_dbug, al_none  },
  { "HELP", cmd_help, al_none  },
  { "MOTD", cmd_motd, al_none  },
  { "NOOP", cmd_noop, al_none  },
  { "QUIT", cmd_quit, al_none  },
  { "REGU", cmd_regu, al_none  },
  { "USER", cmd_user, al_none  },
  
  { "ELOG", cmd_elog, al_read  },
  { "INDX", cmd_indx, al_read  },
  { "ITEM", cmd_item, al_read  },
  { "STAT", cmd_stat, al_read  },
  
  { "CONT", cmd_cont, al_write },
  { "DATA", cmd_data, al_write },
  { "NEWI", cmd_newi, al_write },
  { "REPL", cmd_repl, al_write },
  
  { "DIFF", cmd_diff, al_edit  },
  { "EDLK", cmd_edlk, al_edit  },
  { "EDUL", cmd_edul, al_edit  },
  { "EDIT", cmd_edit, al_edit  },
  { "EDIX", cmd_edix, al_edit  },
  { "EDAB", cmd_edab, al_edit  },
  { "EDCF", cmd_edcf, al_edit  },
  { "KILL", cmd_kill, al_edit  },
  { "KILR", cmd_kilr, al_edit  },
  { "MOTS", cmd_mots, al_edit  },
  { "UDBM", cmd_udbm, al_edit  },

  { 0 }
};

static void server(void) {
  static char stdinbuf[INPUTLINE_MAXLEN+5], stdoutbuf[INPUTLINE_MAXLEN+5];
  char linebuf[INPUTLINE_MAXLEN+5];
  int l, flags;
  const struct commandinfo *cip;
  const char *p;
  char *q;

  mypid= getpid();
  
  close(0); errno=0;
  if (dup(slave)) {
    perror("groggsd: ERROR dup(slave)!=0");
    write(slave,
          "484 Server unexpected error: Failed to reassign stdin.\r\n",56);
    exit(1);
  }
  close(1); errno=0;
  if (dup(slave)!=1) {
    perror("groggsd: ERROR dup(slave)!=1");
    write(slave,
          "484 Server unexpected error: Failed to reassign stdout\r\n",56);
    exit(1);
  }
  setvbuf(stdin,stdinbuf,_IOLBF,INPUTLINE_MAXLEN);
  setvbuf(stdout,stdoutbuf,_IOLBF,INPUTLINE_MAXLEN);

  sprintf(clientid, "%ld %s,%d",
          servseq, inet_ntoa(calleraddr.sin_addr), ntohs(calleraddr.sin_port));

  signal(SIGPIPE,&sigpipehandler);
  
  flags= fcntl(0,F_GETFL,0);
  if (flags == -1) ohshite("Failed fcntl GETFL on client socket");
  flags &= ~O_NDELAY;
  if (fcntl(0,F_SETFL,flags)==-1)
    ohshite("Failed fcntl SETFL on client socket");

  setstatus(0,"Experimental GROGGS system RGTP server ready");
  for (;;) {
    errno= 0;
    settimeout(0, edit ? EDITORINACTIVITY_TIMEOUT : INACTIVITY_TIMEOUT);
    p= fgets(linebuf,INPUTLINE_MAXLEN,stdin);
    if (alarmclosefd== -1) wastimeout();
    if (!p) {
      if (ferror(stdin)) loge(ll_trace,"Read error, closing");
      else log(ll_trace,"End of file, closing");
      exit(0);
    }
    l= strlen(linebuf);
    if (!l) {
      log(ll_trace,"Empty line (not even a newline) received and ignored");
      continue;
    }
    if (linebuf[l-1]!='\n') {
      log(ll_trace,"Line too long (`%.50s...')", linebuf);
      setsupertrace(); fputs("512 Line far too long.\r\n",stdout);
      skiptonewline();
      continue;
    }
    while (l>0 && isspace(linebuf[l-1])) l--;
    if (!l) continue;
    linebuf[l]= 0;
    alarm(0); if (alarmclosefd == -1) wastimeout();
    if (supertrace) log(ll_debug,"<<< %s",linebuf);
    else strcpy(loglinebuf,linebuf);
    for (cip= commandinfos; cip->command; cip++) {
      for (p= cip->command, q=linebuf;
           *p && toupper(*p) == toupper(*q);
           p++, q++);
      if (!*p && (!*q || isspace(*q))) break;
    }
    if (!cip->command) {
      setsupertrace(); log(ll_trace,"Unknown command `%.40s[...]'",linebuf);
      fputs("510 Unknown command.\r\n",stdout);
    } else if (alevel < cip->alevel) {
      ensurelogcmdline();
      log(ll_alert,"530 response to %s.",cip->command); tcpident(); setsupertrace();
      fputs("530 Permission denied as specified in 230/231/232 response.\r\n",
            stdout);
    } else {
      skipspace(&q);
      (cip->function)(q);
    }
  }    
}

static void recordwantrestart(void) { wantrestart=1; }

static void reopenstderr(void) {
  int fd;
  
  fd= open(LOG_FILENAME,O_WRONLY|O_APPEND|O_CREAT,0666);
  if (fd<0) {
    loge(ll_error,"Failed to reopen logging file"); exit(1);
  }
  if (dup2(fd,1) != 1) {
    loge(ll_error,"Failed to dup2 logfile to stdout"); exit(1);
  }
  close(fd);
  if (dup2(1,2) != 2) {
    loge(ll_error,"Failed to dup2 logfile to stderr"); exit(1);
  }
}

static void checkstderr(void) {
  struct stat stab;
  static int checking= 0;

  if (debugserver==1 || checking) return;
  checking++;
  if (fstat(2,&stab)) {
    loge(ll_error,"Failed to fstat logfile (stderr)"); exit(1);
  }
  if (!(stab.st_mode & 0222))  /* no write permission */
    reopenstderr();
  checking--;
}

int main(int argc, char **argv) {
  int master, child;
  struct sockaddr_in sa;
  int cal, i, status, flags;
  unsigned long v;
  struct sigaction act;
  sigset_t nullmask;
  fd_set readfds;
  struct timeval timeout;
  long childstatpid;

  umask(umask(0777) | UMASK_ADD);
  mypid= getpid();
  
  master=-1;
  port= TCPPORT_DEFAULT;
  while (*++argv) {
    if (!strcmp(*argv,"-debug")) {
      debugserver++;
    } else if (!strcmp(*argv,"-master")) {
      if (!*++argv) {
        fputs("groggsd: USAGE No fd number after -master\n",stderr);
        exit(2);
      }
      master= atoi(*argv);
    } else if (!strcmp(*argv,"-port")) {
      if (!*++argv) {
        fputs("groggsd: USAGE No port number after -port\n",stderr);
        exit(2);
      }
      port= atoi(*argv);
    } else {
      fprintf(stderr,"groggsd: INITERROR Unknown option `%s'\n",*argv);
      exit(2);
    }
  }

  if (!debugserver) {
    setvbuf(stderr,0,_IOFBF,512);
    if (chdir(SPOOL_DIR)) {
      perror("groggsd: INITERROR Cannot chdir to " SPOOL_DIR);
      exit(2);
    }
  }
  if (debugserver != 1) reopenstderr();

  if (master<0) {
    master= socket(AF_INET,SOCK_STREAM,0);
    if (master<0) {
      perror("groggsd: Fatal error! Failed to create socket"); exit(1);
    }
    memset(&sa,0,sizeof(sa));
    sa.sin_family= AF_INET;
    for (;;) {
      sa.sin_port= htons(port);
      if (bind(master,(struct sockaddr*)&sa,sizeof(sa)) >=0) break;
      if (errno != EADDRINUSE || debugserver != 1) {
        loge(ll_fatal,"Failed to bind"); exit(1);
      }
      port++;
    }
  } else {
    cal= sizeof(sa);
    errno=0;
    if (getsockname(master,&sa,&cal) || cal != sizeof(sa)) {
      loge(ll_fatal,"Failed to get socket name"); exit(1);
    }
    port= ntohs(sa.sin_port);
  }
  if (listen(master,3) < 0) { loge(ll_fatal,"Failed to listen"); exit(1); }

  v= getpid(); i=32;
  act.sa_handler= SIG_DFL;
  sigemptyset(&nullmask);
  act.sa_mask= nullmask;
  act.sa_flags=
#ifdef SA_INTERRUPT
    SA_INTERRUPT |
#endif
      SA_NOCLDSTOP;
  if (sigaction(SIGCHLD,&act,0)) {
    loge(ll_fatal,"Failed to set SIGCHLD handler"); exit(1);
  }
  act.sa_handler= recordwantrestart;
  act.sa_mask= nullmask;
  act.sa_flags= 
#ifdef SA_INTERRUPT
    SA_INTERRUPT
#else
      0
#endif
        ;
  if (sigaction(SIGUSR2,&act,0)) {
    loge(ll_fatal,"Failed to set SIGUSR2 handler"); exit(1);
  }

  flags= fcntl(master,F_GETFL,0);
  if (flags == -1) {
    loge(ll_fatal,"Failed fcntl GETFL on master socket"); exit(1);
  }
  flags |= O_NDELAY;
  if (fcntl(master,F_SETFL,flags)==-1) {
    loge(ll_fatal,"Failed fcntl SETFL on master socket"); exit(1);
  }

  log(ll_trace,"Started, using port %d",port);

  for (;;) {
    timeout.tv_sec= 3600*2;
    timeout.tv_usec= 0;
    FD_ZERO(&readfds); FD_SET(master,&readfds);
    i= select(master+1,&readfds,(void*)0,(void*)0,&timeout);
    if (i<0 && errno!=EINTR) { loge(ll_fatal ,"Failed to select"); exit(1); }
    while ((childstatpid= waitpid(-1,&status,WNOHANG))>0)
      if (WIFEXITED(status) ? WEXITSTATUS(status) :
          WIFSIGNALED(status) ? WTERMSIG(status)!=SIGPIPE : 1)
        log(ll_error,"Subprocess %ld failed with code %d\n",childstatpid,status);
    if (debugserver != 1) reopenstderr();
    if (wantrestart) {
      char buf[10]; sprintf(buf,"%d",master);
      log(ll_trace,"Caught a SIGUSR2, restarting ...");
      execl(DAEMON_PROGRAM,DAEMON_PROGRAM,"-master",buf,
            debugserver>0 ? "-debug" : (const char*)0,
            debugserver>1 ? "-debug" : (const char*)0,
            (const char*)0);
      loge(ll_error,"Failed to exec replacement daemon");
    }
    cal= sizeof(calleraddr);
    slave= accept(master,(struct sockaddr*)&calleraddr,&cal);
    if (slave < 0) {
      if (errno==EINTR || errno==EWOULDBLOCK) continue;
      perror("groggsd: FATALERROR Failed to accept"); exit(1);
    }
    if (cal != sizeof(calleraddr)) {
      log(ll_fatal,"Length of address is %ld, expected %ld\r\n",
          (long)cal, (long)sizeof(calleraddr));
      write(slave, "484 Server unexpected error: "
                   "Calling address malformatted\r\n",59);
      exit(1);
    }
    servseq++;
    child= fork();
    if (child < 0) {
      loge(ll_error,"Failed to fork");
      write(slave,"484 Server system error: Failed to fork\r\n",41);
      close(slave);
    } else if (child == 0) {
      close(master); server();
    }
    close(slave);
  }
}
