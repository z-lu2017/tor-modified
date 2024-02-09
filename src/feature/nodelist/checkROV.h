#ifndef CHECKROV_H
#define CHECKROV_H
#include <stdio.h>
#include <stdlib.h>
#include "read.h"
#include <string.h>

struct IPNetWork* readMapping(int count);
int ip2ROV(struct IPNetWork* ROVList, char *ip, int ROVcount, int * ASNarray);
int getASN(struct IPNetWork* ROVList, char *ip, int count);
int getROVCount(void);
int * getROVList(void);
// char * getFilePath();

#endif