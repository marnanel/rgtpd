/*
 * Distributed GROGGS  Copyright (C)1994 Ian Jackson
 *
 * File locker
 *
 * It will lock the file argv[1] for writing,
 * feed argv[2] to system(3), and then unlock the file
 *
 * This file written by me, Ian Jackson, in 1993, 1994, 1995.
 * I hereby place it in the public domain.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

#include <sys/wait.h>

#include "ehandle.h"
#include "misc.h"

int main(int argc, char **argv) {
  FILE *file;
  int code;
  
  if (argc != 3) ohshit("lockfile needs 2 args");
  file= fopen(argv[1],"r+"); if (!file) ohshite("lockfile: open %s",argv[1]);
  makelock(file,F_WRLCK,argv[1]);
  errno=0; code= system(argv[2]);
  if (!WIFEXITED(code)) ohshite("lockfile: run %s gave %d",argv[2],code);
  unlock(file,argv[1]);
  return WEXITSTATUS(code);
}
