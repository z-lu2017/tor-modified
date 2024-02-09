#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdint.h>
#include "checkROV.h"
#include "checkROA.h"


#include "app/config/config.h"
#include "core/mainloop/connection.h"
#include "core/or/policies.h"
#include "core/or/reasons.h"
#include "feature/client/entrynodes.h"
#include "feature/dirclient/dirclient.h"
#include "feature/dirclient/dirclient_modes.h"
#include "feature/dircommon/directory.h"
#include "feature/nodelist/describe.h"
#include "feature/nodelist/dirlist.h"
#include "feature/nodelist/microdesc.h"
#include "feature/nodelist/networkstatus.h"
#include "feature/nodelist/node_select.h"
#include "feature/nodelist/nodelist.h"
#include "feature/nodelist/routerlist.h"
#include "feature/nodelist/routerset.h"
#include "feature/relay/router.h"
#include "feature/relay/routermode.h"
#include "lib/container/bitarray.h"
#include "lib/crypt_ops/crypto_rand.h"
#include "lib/math/fp.h"

char path[200] = "/usr/local/share/tor/";
/*
Big Picture Design:
Need to do ROV check on each IP
-ASNwROV.csv has list of AS that has ROV coverage, only ASN contained
-each ROV check only has IP addr as input
-routeviews-rv2-20210722-0200.pfx2as maps ASN to IP

Solution:
-parsa routeview......pfx2as, find out each ASN's prefix boundary and save to 
list of struct
-during rov check, map IP addr to ASN using the above list
-check the ASN in ASNwROV.csv




*/
int getROVCount(void){
    // count the number of line in IP to ASN mapping data file 
    // used to find out the size of malloc
    FILE *fp;
    char * pathFromConfig2 = getFilePath();

    
    // make the pointer and start opening the file 
    strcat(pathFromConfig2, "routeviews-rv2-20230501-1200.pfx2as");
    // open for the first time to count lines in the file 
    fp = fopen(pathFromConfig2, "r");

    // if file open fails print error msg 
    if (fp == NULL){
        printf("error reading file4");
        exit(0);
    }

    // init counter to 0
    int count = 0;
    char line[200]; //giant char to store 1 line in csv
    while (fgets(line, 200, fp) != NULL){
        count += 1;
    }


    // close the file 
    

    // open file again for processing 
    fclose(fp);
    free(pathFromConfig2);
    return count;
}

struct IPNetWork* readMapping(int count){

    // read in IP to ASN data map and store each entry into custom made struct 

    FILE *fp;

    char * pathFromConfig2 = getFilePath();

    // make the pointer and start opening the file 

    strcat(pathFromConfig2, "routeviews-rv2-20230501-1200.pfx2as");
    char line[200]; //giant char to store 1 line in csv
    fp = fopen(pathFromConfig2, "r");
    
    struct IPNetWork* ROVList;
    ROVList = malloc((count)*sizeof *ROVList);
    
    int infoCounter = 0;

    // make a array of IPNetWork structs to store each network in csv file, the size was calculated as count previously 
    

    while (fgets(line, 100, fp) != NULL && infoCounter < count){
        
        char lineArray[3][200]; 
        int octet[4] = {-1,-1,-1,-1};

        // following code separate each line using tab delimiter 
        char * token = strtok(line, "\t");
        int counter = 0;
        while( token != NULL ) {
            
            strcpy(lineArray[counter], token);
            token = strtok(NULL, "\t");
            counter += 1;
        }
        
        // separate each octet from the IP address 
        token = strtok(lineArray[0], ".");
        counter = 0;
        while( token != NULL ) {
            
            octet[counter] =  (unsigned int) atoi(token);
            token = strtok(NULL, ".");
            counter += 1;
        }
    
    //     // assign each line info to custom struct 
        ROVList[infoCounter].firstOctet = octet[0];
        ROVList[infoCounter].secOctet = octet[1];
        ROVList[infoCounter].thirdOctet = octet[2];
        ROVList[infoCounter].fourthOctet = octet[3];
        ROVList[infoCounter].prefix = (unsigned int) atoi(lineArray[1]);
        ROVList[infoCounter].ASN = (unsigned int) atoi(lineArray[2]);
        ROVList[infoCounter].maxBinary = findBoundMax(ROVList[infoCounter].firstOctet, ROVList[infoCounter].secOctet, ROVList[infoCounter].thirdOctet, ROVList[infoCounter].fourthOctet, ROVList[infoCounter].prefix);
        ROVList[infoCounter].minBinary = findBoundMin(ROVList[infoCounter].firstOctet, ROVList[infoCounter].secOctet, ROVList[infoCounter].thirdOctet, ROVList[infoCounter].fourthOctet, ROVList[infoCounter].prefix);
    //     // increment counter to fill next struct 
        infoCounter += 1;
    }

    fclose(fp);
    free(pathFromConfig2);

    return ROVList;
}

int getASN(struct IPNetWork* ROVList, char *ip, int count){
    // separate each octet of input ip into int array 
    char * token = strtok(ip, ".");
    // loop through the string to extract all other tokens
    int octetArr[4] = {0,0,0,0}; // containt 4 octet of the input ip address
    int counter = 0;
    // loop to print all token 
    while( token != NULL ) {
        // store each split item in an array 
        octetArr[counter] = atoi(token);
        token = strtok(NULL, ".");
        counter += 1;
    }

    // target ip address trying to search for ROV coverage 
    uint32_t targetNum = IPtoNumber(octetArr[0],octetArr[1],octetArr[2],octetArr[3]); //use IPtoNumber to convert to integer to compare with each networks bound calculated earlier 
        // init the bound var for each ROA entry 
    uint32_t min = 0;
    uint32_t max = 0;
    int ASN = -1;
    // go through mapping Ip to ASN data to see which ASN the target ip fits in 
    for (int i = 0; i < count; i++){
        min = ROVList[i].minBinary; //get max and min from process list 
        max = ROVList[i].maxBinary;
        // if the address fall between any network's prefix then it has ROA 
        if (targetNum >= min && targetNum <= max){
            ASN = ROVList[i].ASN;
            break;
        }
    }
    return ASN; //return found ASN or return -1 if not found 
}

int * getROVList(void){
    // read in file that contains AS that implements ROV 
    // each AS on new line 
    FILE *fp;
    char * pathFromConfig2 = getFilePath();
    
    // make the pointer and start opening the file 
    strcat(pathFromConfig2, "ASNwROV.csv");
    // count number of entry to create list 
    // open for the first time to count lines in the file 
    fp = fopen(pathFromConfig2, "r");

    // if file open fails print error msg 
    if (fp == NULL){
        printf("5");
        exit(0);
    }

    // init counter to 0
    int count = 0;
    char line[100]; //giant char to store 1 line in csv
    while (fgets(line, 100, fp) != NULL){
        count += 1;
    }


    // close the file 
    

    // open file again for processing 
    fclose(fp);
    int * ASNarray = malloc((count+1)*sizeof(int)); //create list based on size 

    fp = fopen(pathFromConfig2, "r");

    // if file open fails print error msg 
    if (fp == NULL){
        printf("error reading file5");
        exit(0);
    }

    // init counter to 0
    count = 0;

    while (fgets(line, 100, fp) != NULL){
        // put each ASN into malloc array 
        ASNarray[count] = atoi(line);
        count += 1;
    }
    // place -1 to signifiy the end of array 
    ASNarray[count] = -1;
    fclose(fp);
    free(pathFromConfig2);
    return ASNarray;
}

int ip2ROV(struct IPNetWork* ROVList, char *ip, int ROVcount, int * ASNarray){
    int ASN = getASN(ROVList, ip, ROVcount); //get ASN of the IP in question 
    int ROVCovered = 0;
    // check to see if IP got mapped to a valid ASN
    if(ASN != -1){
        int ArrCounter = 0;
        while(ASNarray[ArrCounter] != -1){
            // go through array of AS with ROV to see if the ASN matches or not 
            if (ASNarray[ArrCounter] == ASN){
                ROVCovered = 1;
            }
            ArrCounter += 1;
        }
    }

    return ROVCovered;
}
