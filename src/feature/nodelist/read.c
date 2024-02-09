#include "read.h"
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>

// takes in a line of csv input in roa file and get the 
// ip network out of the line and store inside a int array 
//called here in checkROA.c:processROAcsv, used to parse 20200913.csv
int * lineTOIPNetwork(char input[]){
    
    // find the substring that contains the ip network 
    int startIndex = -1;
    int endIndex = -1;
    char comma = ',';
    char *ipSub; // declare the pointer to store the sub string 
    int IPV6 = 0; //set ipv6 to 0 means its not ipv6 network initially 
    for(int i = 0; i < strlen(input); i++){

        // if colon is present in a line, then set ipv6 as 1 aka true 
        if (input[i] == ':'){
            IPV6 = 1;
        }
        
    }

    int *octet = (int*)malloc(5*sizeof(int));
    octet[0] = 9999; //array to store the four octet and the prefix of a ip network 
    octet[1] = 9999;
    octet[2] = 9999;
    octet[3] = 9999;
    octet[4] = 9999;
    // if not ipv6
    if (IPV6 == 0){
        char * token = strtok(input, ",");
        token = strtok(NULL, ",");
        char * prefix = strtok(token, "/");
        prefix = strtok(NULL, "/");
        octet[4] = (unsigned int) atoi(prefix);
        
        int count = 0;
        token = strtok(token, ".");
        while( token != NULL ) {
            octet[count] = (unsigned int) atoi(token);
            token = strtok(NULL, ".");
            count += 1;
        }
    } 
    
    return octet;
}
  
// get substring from char array and return as ptr to char array 
//not functional anymore!!!, used token function instead
char *getSubString(int start, int end, char input[]){
    
    char *result = malloc((end-start)*sizeof(char));
    for(int i = start; i < end; i++){
        result[i - start] = input[i];
    }

    return result;
} 
// function that calculates the highest addr in ip network 

//input each octet of ip addr + prefix to find the highest addr in the prefix 
uint32_t findBoundMax(uint32_t n1, uint32_t n2, uint32_t n3, uint32_t n4, int prefix){

    uint32_t result = 0x00000000;
    result = result | (n1 << 24);

    result = result | (n2 << 16);

    result = result | (n3 << 8);

    result = result | n4;


    uint32_t minMask = 0xFFFFFFFF;
    minMask = minMask << (32-prefix);

    uint32_t maxMask = ~minMask;

    uint32_t max = result | maxMask;
    uint32_t min = result & minMask;
    return max;
}
// convert ip addr into integer value 
//convert ip to number in hex
uint32_t IPtoNumber(uint32_t n1, uint32_t n2, uint32_t n3, uint32_t n4){
    uint32_t result = 0x00000000;
    result = result | (n1 << 24);

    result = result | (n2 << 16);

    result = result | (n3 << 8);

    result = result | n4;
    return result;
}

// function that calculates the lowerst addr in ip network 
//get min of a prefix
//findBoundmin, findBoundMax and IPtoNumber are used to find if a ip is belongs to a ROA
//first parse 20200913.csv to find prefix of all ROA AS, then see if a set IP is in 
//a prefix to determine ROA coverage.
uint32_t findBoundMin(uint32_t n1, uint32_t n2, uint32_t n3, uint32_t n4, int prefix){
    
    uint32_t result = 0x00000000;
    result = result | (n1 << 24);

    result = result | (n2 << 16);

    result = result | (n3 << 8);

    result = result | n4;


    uint32_t minMask = 0xFFFFFFFF;
    minMask = minMask << (32-prefix);

    uint32_t maxMask = ~minMask;

    uint32_t max = result | maxMask;
    uint32_t min = result & minMask;
    return min;
}



