/*
 * Distributed GROGGS  Copyright (C)1993 Ian Jackson
 *
 * User database manager
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
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>

#include "ehandle.h"
#include "misc.h"
#include "userdb.h"

static void usage(const char *fmt, ...) {
  va_list ap;

  if (fmt) {
    va_start(ap,fmt);
    vfprintf(stderr,fmt,ap);
    va_end(ap);
    fputs("\n\n",stderr);
  }
  if (!
      fputs("Usage:\n"
            "  udbmanage -?|--help\n"
            "  udbmanage [opts] -l|--list [userid[/[access]] ...]\n"
            "  udbmanage [opts] [-c|-u|-d|--create|--update|--delete]\n"
            "                      userid[/[access]] values ...\n"
            "  udbmanage [opts] -s|--status|-t|--tidytest|--tidy\n"
            "Options:\n"
            "   -v|-q|--verbose|--quiet\n"
            "   -f|--file filename\n"
            "   -s|--status\n"
            "   --restrict\n"
            "   --noprompt\n"
            "   --secret\n"
            "   --size nentries\n"
            "Values:\n"
            "   copyfrom=<userid[/access]>\n"
            "   ident=none|md5|md5new\n"
            "   lastref=<hex-seconds>\n"
            "   disable|enable\n"
            "   setsecret     (reads 8 hex digits from stdin)\n", stderr))
    ohshite("Failed to write usage message to stderr");
  exit(fmt ? 2 : 0);
}

struct optinfo {
  char shortname;
  const char *longname;
  int takesarg;
  int *storeat, value;
  void (*fn)(const char *value);
};

enum modes { mo_list, mo_create, mo_update, mo_delete, mo_tidy, mo_tidytest, mo_scan };
enum yesno { yn_no, yn_yes };

static int mode=-1; /* one of the modes */
static int noprompt=-1; /* each of these is a yesno */
static int showsecret=-1, status=-1, verbose=-1, restricted=-1;
static int secretbytes=-1;
static unsigned char secret[SECRET_MAXBYTES];
static int ident=-1, disabled=-1;
static u32 lastref= ~0U;
static const char *udbfile= 0;
static long newsize= -1;
static int exitstatus= 0;

static time_t currenttime;
  
static int tallytotal, tallyfull, tallytotaldelay;

static int getenum(const char *v, const char *const *l, const char *w) {
  int i=0;
  while (*l && strcmp(v,*l)) { l++; i++; }
  if (!*l) usage("%s value `%s' unknown",w,v);
  return i;
}

static const char *const acs[]={ "none","read","write","edit",0 };
static const char *const ids[]={ "none","md5new","md5",0 };

static void of_file(const char *file) {
  if (restricted>=0) usage("--file option not available in restricted access mode");
  if (udbfile) usage("--file option repeated");
  udbfile= file;
}

static void of_size(const char *sz) {
  long v;
  char *e;
  
  v= strtol(sz,&e,10);
  if (*e) usage("--size value contains garbage");
  newsize= v;
}

static void of_help(const char *nullpointer) { usage(0); }

static const struct optinfo optinfos[]= {
  { '?', "help",      0,  0,           0,           of_help  },
  { 'l', "list",      0,  &mode,       mo_list,     0        },
  { 'c', "create",    0,  &mode,       mo_create,   0        },
  { 'u', "update",    0,  &mode,       mo_update,   0        },
  { 'd', "delete",    0,  &mode,       mo_delete,   0        },
  {  0,  "tidy",      0,  &mode,       mo_tidy,     0        },
  { 't', "tidytest",  0,  &mode,       mo_tidytest, 0        },
  { 's', "status",    0,  &status,     yn_yes,      0        },
  { 'v', "verbose",   0,  &verbose,    yn_yes,      0        },
  {  0,  "restrict",  0,  &restricted, yn_yes,      0        },
  {  0,  "noprompt",  0,  &noprompt,   yn_yes,      0        },
  { 'q', "quiet",     0,  &verbose,    yn_no,       0        },
  { 'f', "file",      1,  0,           0,           of_file  },
  {  0,  "secret",    0,  &showsecret, yn_yes,      0        },
  {  0,  "size",      1,  0,           0,           of_size  },
  {  0,   0 }
};

static void display(const struct userentry *uep) {
  if (verbose >0)
    printf("%08x  ",uep->lastref);
  else
    printf("%7d  ",(u32)((currenttime-uep->lastref)/3600));
  
  if ((unsigned)uep->access+1 >= sizeof(acs)/sizeof(*acs))
    printf("??%-4d ",uep->access);
  else
    printf("%-6s ",acs[(int)uep->access]);
  fputs(uep->disabled ? "disabled " : "enabled  ",stdout);
  
  if ((unsigned)uep->ident+1 >= sizeof(ids)/sizeof(*ids))
    printf("??%-5d ",uep->ident);
  else
    printf("%-7s ",ids[(int)uep->ident]);
  
  if (showsecret > 0) {
    if (uep->secretbytes > SECRET_MAXBYTES)
      ohshit("database corrupted - secret too long");
    sendhex(uep->secret,uep->secretbytes);
    printf("%*s",2+SECRET_MAXBYTES-uep->secretbytes*2,"");
  }
  printf("%.*s\n",USERID_MAXLEN,uep->userid);
  if (ferror(stdout)) ohshite("Write error");
}

static void tally(const struct userentry *uep) {
  tallytotal++;
  if (*uep->userid) tallyfull++;
}

static void showstatus(void) {
  printf("%d slots,  %d empty,  %d full,  %.1f%% full\n",
         tallytotal, tallytotal-tallyfull, tallyfull,
         100.0*tallyfull/(double)tallytotal);
  if (mode == mo_tidy || mode == mo_tidytest)
    printf("%d delays,  %.3f mean delay\n",
           tallytotaldelay, tallytotaldelay/(double)tallyfull);
  printf("each slot is %ld bytes, file is %ld bytes\n",
         (long)sizeof(struct userentry),
         (long)sizeof(struct userentry)*tallytotal);
  if (ferror(stdout)) ohshite("Write error for status");
}

static int listorscan(const char *usok, const int ac, int scanonly) {
  FILE *file;
  struct userentry ue;
  int gaps=0, i=0, nf=0;

  file= fopen(udbfile,"rb");
  makelock(file,F_RDLCK,udbfile);
  if (!file) ohshite("User database `%s' inaccessible for scan",udbfile);
  for (;;) {
    errno=0; if (fread(&ue,sizeof(ue),1,file)!=1) break;
    if (!scanonly) {
      if (*ue.userid &&
          (!usok || !strncmp(usok,ue.userid,USERID_MAXLEN)) &&
          (ac<0 || ac == ue.access)) {
        if (!usok) {
          if (verbose == yn_yes) printf("%3d gap  ",gaps);
          if (verbose != yn_no) printf("%4d:  ",i);
          /* we don't need to check for errors here as display()
             ends with a check using ferror(). */
        }
        display(&ue); gaps=0; nf++;
      } else {
        gaps++;
      }
    }
    i++;
    if (status>=0) tally(&ue);
  }
  if (!usok && verbose == yn_yes)
    if (printf("%3d gap\n",gaps)==EOF) ohshite("Write count of gaps at end");
  if (ferror(file)) ohshite("Read error on user database `%s'",udbfile);
  ufclose(file,udbfile);
  return nf;
}

static const char *dispuserac(const char usok[USERID_MAXLEN], int ac) {
  static char buf[USERID_MAXLEN+100];
  strcpy(buf,"User `");
  strncat(buf,usok,USERID_MAXLEN);
  strcat(buf,"'");
  if (ac >= 0) {
    strcat(buf," access=");
    strcat(buf,acs[ac]);
  }
  return buf;
}

static const char *parseuserac(char *usreq, char usok[USERID_MAXLEN], int *acp) {
  char *r;
  const char *e;
  
  *acp= -1;
  r= strrchr(usreq,'/');
  if (r) {
    *r++= 0;
    if (*r) *acp= getenum(r,acs,"access");
  } 
  e= userdb_checkid(usreq,usok);  if (e) return e;
  return 0;
}

static void listsingle(char *usreq) {
  char usok[USERID_MAXLEN];
  int ac;
  int nf;
  const char *e;

  e= parseuserac(usreq,usok,&ac);
  if (e) { fprintf(stderr,"Userid/access `%s' %s\n",usreq,e); exit(2); }
  nf= listorscan(usok,ac,0);
  if (!nf) {
    fprintf(stderr,"%s not found\n", dispuserac(usok,ac)); exitstatus=1; return;
  }
}

static void writefail_attemptrecover(const char *whatfailed,
                                     FILE *file,
                                     const char *filename,
                                     const struct userentry *ouea,
                                     int sizetowrite) {
  int exitstatus;
  unsigned char *p;
  int towrite;
  int fd;
  int written;

  exitstatus= 1;
  fprintf(stderr,
          "Failed to %s user database `%s', attempting to restore old version ...\n",
          whatfailed, filename);
  if ((fd= open(filename,O_RDWR)) <0) {
    perror("Failed to reopen file"); exit(3);
  }
  if (ftruncate(fd,sizeof(struct userentry)*sizetowrite)) {
    perror("Failed to truncate to original size - continuing anyway");
    exitstatus= 3;
  }
  if (lseek(fd,0,SEEK_SET)) {
    perror("Failed to seek back to beginning of database"); exit(3);
  }

  for (p= (unsigned char*)ouea, towrite= sizeof(struct userentry)*sizetowrite,file;
       towrite;
       p+=written, towrite-=written) {
    written= write(fd,p,towrite);
    if (written < 0) {
      perror("Failed to write old data back into database"); exit(3);
    }
  }
  if (close(fd)) {
    perror("Failed to close after writing old data back"); exit(3);
  }
  _exit(exitstatus);
}

static void tidyall(void) {
  FILE *file;
  int i,thisdelay,pref,oldsize;
  struct stat ustab;
  unsigned long hash;
  struct userentry *uea, *ouea, *ueap;

  file= fopen(udbfile,mode == mo_tidy ? "r+b" : "rb");
  if (!file) ohshite("User database `%s' inaccessible",udbfile);
  makelock(file,mode==mo_tidy?F_WRLCK:F_RDLCK,udbfile);
  if (fstat(fileno(file),&ustab)) ohshite("User database `%s' unstattable",udbfile);
  oldsize= ustab.st_size / sizeof(struct userentry);
  if (newsize == -1) {
    if (ustab.st_size % sizeof(struct userentry))
      ohshit("User database `%s' has non-integral number of records;\n"
             "May be able to fix with --size option",udbfile);
    newsize= oldsize;
  } else {
    if (ustab.st_size % sizeof(struct userentry))
      if (fprintf(stderr,
                  "Warning - ignoring partial record (%d bytes) at end of `%s'.\n",
                  (int)(ustab.st_size % sizeof(struct userentry)), udbfile)
          ==EOF) ohshite("Failed to write warning to stderr");
  }
  tallyfull= 0;
  uea= calloc(sizeof(struct userentry),newsize);
  ueap= ouea= malloc(sizeof(struct userentry)*oldsize);
  if (!uea || !ouea) ohshite("Failed to allocate memory for working copies of data");
  tallyfull= 0;
  for (;;) {
    errno=0; if (fread(ueap,sizeof(*ueap),1,file)!=1) break;
    if (!*ueap->userid) { ueap++; continue; }
    if (tallyfull == newsize) ohshit("New database overfull - giving up");
    hash= userdb_hash(ueap->userid);
    pref= i= hash % newsize;
    thisdelay=0;
    for (;;) {
      if (!*uea[i].userid) break;
      i++; i %= newsize;
      thisdelay++;
    }
    if (verbose == yn_yes) {
      printf("%3d delay   hash %08lX -> %4d    %4d:  ",thisdelay,hash,pref,i);
      display(ueap);
    }
    uea[i]= *ueap;
    tallyfull++;
    tallytotaldelay+=thisdelay;
    ueap++;
  }
  if (ferror(file)) ohshite("User database `%s' unreadable for tidy",udbfile);
  if (mode == mo_tidy) {
    rewind(file);
    errno=0; if (fwrite(uea,sizeof(struct userentry),newsize,file)!=newsize)
      writefail_attemptrecover("write to",file,udbfile,ouea,oldsize);
    if (fflush(file))
      writefail_attemptrecover("flush",file,udbfile,ouea,oldsize);
    if (ftruncate(fileno(file),sizeof(struct userentry)*newsize))
      writefail_attemptrecover("truncate",file,udbfile,ouea,oldsize);
  }
  if (ufclose(file,udbfile))
    ohshite("AARGH! Failed to close user database `%s', possible corruption",udbfile);
  tallytotal= newsize;
}

static void deletesingle(char *usreq) {
  struct userentry ue;
  const struct userentry *uep;
  const char *e;
  int ret, ac;

  e= parseuserac(usreq,ue.userid,&ac);  ue.access=ac;
  if (e) { fprintf(stderr,"Userid `%s' %s\n",usreq,e); exit(2); }
  uep= userdb_find(udbfile,ue.userid,ue.access);
  if (!uep) {
    fprintf(stderr,"%s not found in `%s'\n",dispuserac(ue.userid,ue.access),udbfile);
    exit(1);
  }
  if (verbose == yn_yes) { fputs("Deleting: ",stdout); display(uep); }
  ret= userdb_change(udbfile,&ue, -1);
  if (!ret) return;
  fprintf(stderr,"%s disappeared from `%s'\n",dispuserac(ue.userid,ue.access),udbfile);
  exit(1);
}

static void updatesingle(char *usreq) {
  char usok[USERID_MAXLEN];
  const struct userentry *uep;
  struct userentry ue;
  const char *e;
  int ret, ac;

  e= parseuserac(usreq,usok,&ac);
  if (e) { fprintf(stderr,"Userid `%s' %s\n",usreq,e); exit(2); }
  if (mode != mo_create) {
    /* Changed by MJH 04/07/03: use -1 rather than ac, which should
       allow us to give or take away editor status with the update
       command */
    uep= userdb_find(udbfile,usok,-1);
    if (!uep) ohshit("%s not found in `%s'",dispuserac(usok,ac),udbfile);
    ue= *uep;
    if (verbose == yn_yes) { fputs("Old: ",stdout); display(&ue); }
  } else {
    strncpy(ue.userid,usok,USERID_MAXLEN);
    ue.access= ac>=0 ? ac : al_none;
    ue.ident= uil_none;
    ue.disabled= 0;
    ue.secretbytes= 0;
    memset(ue.secret,0,SECRET_MAXBYTES);
  }
  if (ac >=0) ue.access= ac;
  if (ident >=0) ue.ident= ident;
  if (disabled >=0) ue.disabled= disabled;
  ue.lastref= (lastref != ~0U) ? lastref : currenttime;
  if (ue.access==al_edit && ue.ident==uil_none && !ue.disabled)
    fprintf(stderr,
            "Warning - user `%.*s': edit access and enabled but no id confirmation\n",
            USERID_MAXLEN,usok);
  if (ue.access==al_none && ue.ident!=uil_none)
    fprintf(stderr,
            "Warning - user `%.*s': no access, but some id confirmation\n",
            USERID_MAXLEN,usok);
  if (secretbytes >=0) {
    ue.secretbytes= secretbytes;
    memcpy(ue.secret,secret,SECRET_MAXBYTES);
  }
  ret= userdb_change(udbfile,&ue, mode==mo_update ? 0 : 2);
  switch (ret) {
  case 0:
    if (verbose == yn_yes) fputs("New: ",stdout);
    /* Don't have to check write errors because display() does. */
    if (verbose != yn_no) display(&ue);
    return;
  case 1:
    fprintf(stderr, "%s %s in `%s'\n",
            dispuserac(ue.userid,ue.access),
            mode==mo_update ? "not found for update" : "already exists",
            udbfile);
    exit(1);
  case 2:
    fprintf(stderr,"Database `%s' is full\n",udbfile);
    exit(1);
  }
}

int main(int argc, char **argv) {
  char *p, *u, *ep;
  int c;
  const struct optinfo *oip;
  const char *e;
  const struct userentry *copyfrom;
  char usok[USERID_MAXLEN];
  int ac, n;
  char hbuf[SECRET_MAXBYTES*2+2];

  while ((p= *++argv) !=0) {
    if (*p != '-') {
      break;
    } else if (*++p != '-') {
      while ((c= *p++) !=0) {
        for (oip= optinfos; oip->longname && oip->shortname != c; oip++);
        if (!oip->longname) usage("`-%c' option unknown",c);
        if (oip->storeat) {
          if (*oip->storeat != -1) usage("-%c option repeated or conflicting",c);
          *oip->storeat= oip->value;
        }
        if (oip->takesarg) {
          if (!*p) {
            p= *++argv;
            if (!p) usage("-%c option takes an argument",oip->shortname);
          }
          oip->fn(p); break;
        } else {
          if (oip->fn) oip->fn(0);
        }
      }
    } else {
      ++p;
      for (oip= optinfos; oip->longname && strcmp(oip->longname,p); oip++);
      if (!oip->longname) usage("`--%s' option unknown",p);
      if (oip->storeat) {
        if (*oip->storeat != -1)
          usage("--%s option repeated or conflicting",oip->longname);
        *oip->storeat= oip->value;
      }
      if (oip->takesarg) {
        p= *++argv;
        if (!p) usage("--%s option needs a following argument",oip->longname);
        oip->fn(p);
      } else {
        if (oip->fn) oip->fn(0);
      }
    }
  }
  if (mode < 0) {
    if (status>=0) {
      if (p) usage("--status not allowed with specific users");
      mode= mo_scan;
    } else {
      if (!p) usage("no mode of operation and no userids specified");
      mode= mo_list;
    }
  }
  currenttime= time((time_t*)0);
  if (currenttime == (time_t)-1) ohshite("Get current time");
  if (!udbfile) udbfile= SPOOL_DIR USERDB_FILENAME;
  switch (mode) {
  case mo_update: case mo_create:
    if (status >=0 || newsize>=0)
      usage("--size/--status not allowed when updating a record");
    u=p;
    while ((p= *++argv) !=0) {
      if (!strcmp(p,"setsecret")) {
        if (verbose != yn_no && noprompt != yn_yes)
          fputs("Enter secret in hex: ",stderr);
        errno=0; e=fgets(hbuf,SECRET_MAXBYTES*2+2,stdin);
        if (!e) {
          if (ferror(stdin)) ohshite("reading new secret");
          fputs("new shared secret missing\n",stderr); exit(2);
        }
        n= strlen(hbuf);
        if (n) {
          if (hbuf[--n] != '\n') {
            fputs("newline after new shared secret missing -"
                  " secret too long?",stderr);
            exit(2);
          }
          hbuf[n]=0;
        }
        if (n&1) {
          fputs("need even number of hex digits for secret",stderr); exit(2);
        }
        n/=2; memset(secret,0,SECRET_MAXBYTES);
        p=hbuf; if (!scanhex(&p,n,secret)) {
          fputs("secret contained non-hex-digit",stderr); exit(2);
        }
        secretbytes= n;
        showsecret= yn_yes;
      } else if (!strncmp(p,"disable",7)) {
        disabled= 1;
      } else if (!strncmp(p,"enable",6)) {
        disabled= 0;
      } else if (!strncmp(p,"ident=",6)) {
        ident= getenum(p+6,ids,"ident");
      } else if (!strncmp(p,"lastref=",8)) {
        lastref= strtoul(p+8,&ep,16);
        if (*ep) usage("value for lastref must be a hex number");
      } else if (!strncmp(p,"copyfrom=",9)) {
        e= parseuserac(p+9,usok,&ac);
        if (e) { fprintf(stderr,"Copyfrom userid `%s' %s\n",p+9,e); exit(2); }
        copyfrom= userdb_find(udbfile,usok,ac);
        if (!copyfrom) {
          fprintf(stderr,"Copyfrom userid %s not found.\n",dispuserac(usok,ac));
          exit(1);
        }
        ident= copyfrom->ident;
        secretbytes= copyfrom->secretbytes;
        memcpy(secret,copyfrom->secret,SECRET_MAXBYTES);
        lastref= copyfrom->lastref;
      } else {
        usage("unknown value setting `%s'",p);
      }
    }
    updatesingle(u);
    break;
  case mo_list: case mo_scan:
    if (newsize>=0) usage("--size not allowed with --list/--status");
    if (!p) {
      listorscan(0,-1, mode != mo_list);
      if (status >=0) showstatus();
    } else {
      do { listsingle(p); } while ((p= *++argv) !=0);
    }
    break;
  case mo_delete:
    if (newsize>=0 || status>=0) usage("--status/--size not allowed with --delete");
    if (!p) usage("must supply a record to be deleted");
    if (*++argv) usage("may only delete one record at once");
    deletesingle(p);
    break;
  case mo_tidy: case mo_tidytest:
    if (showsecret>=0) usage("--secret not allowed with --tidy[test]");
    if (mode == mo_tidytest && status<0 && verbose<yn_yes) status= yn_yes;
    if (p) usage("userid(s) not allowed with --tidy[test]");
    tidyall();
    if (status >=0) showstatus();
    break;
  default:
    ohshit("Unknown operation mode code %d",mode);
  }
  exit(exitstatus);
}
