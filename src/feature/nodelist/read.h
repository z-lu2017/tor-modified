#ifndef READ_H
#define READ_H

#include <stdio.h>
#include <stdint.h>

// custom struct to store ip network with boundary calculated 
extern struct IPNetWork {
   unsigned int firstOctet;
   unsigned int secOctet;
   unsigned int thirdOctet;
   unsigned int fourthOctet;
   int prefix; 
   uint32_t minBinary; 
   uint32_t maxBinary; 
   int ASN;
} IPNetWork; 

extern struct IPNetWorkASN {
   unsigned int firstOctet;
   unsigned int secOctet;
   unsigned int thirdOctet;
   unsigned int fourthOctet;
   int prefix; 
   uint32_t minBinary; 
   uint32_t maxBinary; 
   int ASN;
} IPNetWorkASN; 

// struct to store addr seapareted into octets 
extern struct Address {
   unsigned int firstOctet;
   unsigned int secOctet;
   unsigned int thirdOctet;
   unsigned int fourthOctet;
} Address; 

// function prototype 
int *lineTOIPNetwork(char input[]);
char *getSubString(int start, int end, char input[]);
uint32_t findBoundMin(uint32_t n1, uint32_t n2, uint32_t n3, uint32_t n4, int prefix);
uint32_t findBoundMax(uint32_t n1, uint32_t n2, uint32_t n3, uint32_t n4, int prefix);
uint32_t IPtoNumber(uint32_t n1, uint32_t n2, uint32_t n3, uint32_t n4);
#endif