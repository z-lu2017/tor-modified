#ifndef CHECKROA_H
#define CHECKROA_H
#include <stdio.h>
#include <stdlib.h>
#include "read.h"
#include <string.h>

int processListofIP(void);
int getCount(void);
struct IPNetWork* processROAcsv(int count);
int checkROA(struct IPNetWork* ROAList, char *ip, int count);
char * getFilePath(void);

#endif