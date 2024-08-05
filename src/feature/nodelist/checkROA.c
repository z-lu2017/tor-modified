#include <stdio.h>
#include <stdlib.h>
#include "checkROA.h"
#include <string.h>


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
#include "lib/fs/files.h"

/*
Big Picture Design:
20200913.csv contains all prefix with ROA coverage
goal: find out which IP has ROA coverage 
solution: 
1.store all entry in .csv into list of structs 
2.in each struct calculate the max and min addr of the prefix 
3.for each ROA check, parse the whole list of struct to see if the ip in questions fits in any
of entry's max and min value 




*/

#define BUF_SIZE 65536
char * pathFromConfig = NULL;

char * getFilePath(){
    // get file path to shared directory from config.c, avoid hard coding file path
    // SHARE_DATADIR PATH_SEPARATOR "tor" PATH_SEPARATOR
    char * path = malloc(200*sizeof(char));
    
    strcpy(path, SHARE_DATADIR);
    strcat(path, PATH_SEPARATOR);
    strcat(path, "tor");
    strcat(path, PATH_SEPARATOR);

    return path;
}

int getCount(void){
    // make the pointer and start opening the file 
    FILE *fp;
    char * pathFromConfig = getFilePath();
    strcat(pathFromConfig, "20240501.csv");
    // open for the first time to count lines in the file 
    //char pathFromConfig[100] = "/home/ubuntu/TOR-RPKI/TOR-RPKI_Siyang/sim_roa_rov_L2/both.txt";
    fp = fopen(pathFromConfig, "r");

    char buf[BUF_SIZE];
    int counter = 0;
    for(;;)
    {
        size_t res = fread(buf, 1, BUF_SIZE, fp);
        if (ferror(fp))
            return -1;

        int i;
        for(i = 0; i < res; i++)
            if (buf[i] == '\n')
                counter++;

        if (feof(fp))
            break;
    }
    fclose(fp);
    free(pathFromConfig);
    return counter;

}

struct IPNetWork* processROAcsv(int count){
    //this function processes the ROA csv file and checks a list of IPs for ROA coverage 
    
    
    FILE *fp;

    char * pathFromConfig = getFilePath();
    
    strcat(pathFromConfig, "20240501.csv");
    char line[100]; //giant char to store 1 line in csv
    fp = fopen(pathFromConfig, "r");
    if (fp == NULL){
        printf("error reading file processROAcsv");
        exit(0);
    }
    // skip the header line so it doesnt get processed 
    fgets(line, 100, fp);

    int * octets; //ptr to store the parsed ip of each line 

    // make a array of IPNetWork structs to store each network in csv file, the size was calculated as count previously 
    struct IPNetWork* ROAList; 
    ROAList = malloc((count)*sizeof *ROAList);

    
    // keep counter to go through every line in file 
    int counter = 0;
    while (fgets(line, 100, fp) != NULL){

        octets = lineTOIPNetwork(line);
        // the read.c file sets all field to -1 if it is ipv6
        if (octets[0] != -1){
            // populate the struct with info parsed using lineTOIPNetwork 
            ROAList[counter].firstOctet = octets[0];
            ROAList[counter].secOctet = octets[1];
            ROAList[counter].thirdOctet = octets[2];
            ROAList[counter].fourthOctet = octets[3];
            ROAList[counter].prefix = octets[4];
            ROAList[counter].maxBinary = findBoundMax(ROAList[counter].firstOctet, ROAList[counter].secOctet, ROAList[counter].thirdOctet, ROAList[counter].fourthOctet, ROAList[counter].prefix);
            ROAList[counter].minBinary = findBoundMin(ROAList[counter].firstOctet, ROAList[counter].secOctet, ROAList[counter].thirdOctet, ROAList[counter].fourthOctet, ROAList[counter].prefix);
            
            
        }else{
            // if its ipv6 set max and min to 0 to skip this entry in the search 
            ROAList[counter].firstOctet = octets[0];
            ROAList[counter].secOctet = octets[1];
            ROAList[counter].thirdOctet = octets[2];
            ROAList[counter].fourthOctet = octets[3];
            ROAList[counter].prefix = octets[4];
            ROAList[counter].maxBinary = 0;
            ROAList[counter].minBinary = 0;

        }
        counter = counter + 1;
        free(octets);
    }
    
    fclose(fp);
    free(pathFromConfig);

    return ROAList;
}

int checkROA(struct IPNetWork* ROAList, char *ip, int count){
    //NEED TO VERIFY IP IS IPV4 BEFORE CALLING THIS FUNC
    // use c func to split at dot dilimeter 
    // source of split func: https://www.educative.io/edpresso/splitting-a-string-using-strtok-in-c
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

    // printf("printing IP here");
    // printf("%d",octetArr[0]);
    // printf("%d",octetArr[1]);
    // printf("%d",octetArr[2]);
    // printf("%d",octetArr[3]);

    // target ip address trying to search for ROA coverage 
    uint32_t targetNum = IPtoNumber(octetArr[0],octetArr[1],octetArr[2],octetArr[3]); //use IPtoNumber to convert to integer to compare with each networks bound calculated earlier 

    // init the bound var for each ROA entry 
    uint32_t min = 0;
    uint32_t max = 0;
    int found = 0;
    for (int i = 0; i < count; i++){
        min = ROAList[i].minBinary; //get max and min from process list 
        max = ROAList[i].maxBinary;
        // if the address fall between any network's prefix then it has ROA 
        if (targetNum >= min && targetNum <= max){
            found = 1;
            break;
        }
    }
    return found;
}

//------------------------------------------------------------------------------------------------------------------------------------------------------------
// used for testing by mass inputting params 
int processListofIP(void){
    //this function processes the ROA csv file and checks a list of IPs for ROA coverage 

    // make the pointer and start opening the file 
    FILE *fp;
    if(pathFromConfig == NULL){
        pathFromConfig = getFilePath();
    }
    strcat(pathFromConfig, "20240501.csv");
    // open for the first time to count lines in the file 
    fp = fopen(pathFromConfig, "r");
    // if file open fails print error msg 
    if (fp == NULL){
        printf("error reading file1");
        exit(0);
    }

    // init counter to 0
    int count = 0;
    char line[100]; //giant char to store 1 line in csv
    while (fgets(line, 100, fp) != NULL){
        count += 1;
    }
    // minus 1 from total count to ignore the header line 
    count = count -1;

    // close the file 
    

    // open file again for processing 
    fclose(fp);
    
    fp = fopen(strcat(pathFromConfig, "20240501.csv"), "r");
    // skip the header line so it doesnt get processed 
    fgets(line, 100, fp);

    int * octets; //ptr to store the parsed ip of each line 

    // make a array of IPNetWork structs to store each network in csv file, the size was calculated as count previously 
    struct IPNetWork* ROAList = malloc((count)*sizeof *ROAList);
    
    // keep counter to go through every line in file 
    int counter = 0;
    while (fgets(line, 100, fp) != NULL){
    
        octets = lineTOIPNetwork(line);
        // the read.c file sets all field to -1 if it is ipv6
        if (octets[0] != -1){
            // populate the struct with info parsed using lineTOIPNetwork 
            ROAList[counter].firstOctet = octets[0];
            ROAList[counter].secOctet = octets[1];
            ROAList[counter].thirdOctet = octets[2];
            ROAList[counter].fourthOctet = octets[3];
            ROAList[counter].prefix = octets[4];
            ROAList[counter].maxBinary = findBoundMax(ROAList[counter].firstOctet, ROAList[counter].secOctet, ROAList[counter].thirdOctet, ROAList[counter].fourthOctet, ROAList[counter].prefix);
            ROAList[counter].minBinary = findBoundMin(ROAList[counter].firstOctet, ROAList[counter].secOctet, ROAList[counter].thirdOctet, ROAList[counter].fourthOctet, ROAList[counter].prefix);
            
            
        }else{
            // if its ipv6 set max and min to 0 to skip this entry in the search 
            ROAList[counter].firstOctet = octets[0];
            ROAList[counter].secOctet = octets[1];
            ROAList[counter].thirdOctet = octets[2];
            ROAList[counter].fourthOctet = octets[3];
            ROAList[counter].prefix = octets[4];
            ROAList[counter].maxBinary = 0;
            ROAList[counter].minBinary = 0;

        }
        counter = counter + 1;

    }


    // open the inputFile file 
    FILE *tfp; 
    tfp = fopen("testinput.csv", "r");

    // if file open fails print error msg 
    if (tfp == NULL){
        printf("error reading file2");
        exit(0);
    }

    char Inputline[100]; //giant char to store 1 line in csv
    while (fgets(Inputline, 100, tfp) != NULL){
        // use c func to split at dot dilimeter 
        // source of split func: https://www.educative.io/edpresso/splitting-a-string-using-strtok-in-c
        char * token = strtok(Inputline, ".");
        // loop through the string to extract all other tokens
        int octetArr[4] = {0,0,0,0}; // containt 4 octet of the input ip address
        counter = 0;
        // loop to print all token 
        while( token != NULL ) {
            // store each split item in an array 
            octetArr[counter] = atoi(token);
            token = strtok(NULL, ".");
            counter += 1;
        }

        // target ip address trying to search for ROA coverage 
        uint32_t targetNum = IPtoNumber(octetArr[0],octetArr[1],octetArr[2],octetArr[3]); //use IPtoNumber to convert to integer to compare with each networks bound calculated earlier 

        // init the bound var for each ROA entry 
        uint32_t min = 0;
        uint32_t max = 0;
        int found = 0;
        for (int i = 0; i < count; i++){
            min = ROAList[i].minBinary; //get max and min from process list 
            max = ROAList[i].maxBinary;
            // if the address fall between any network's prefix then it has ROA 
            if (targetNum >= min && targetNum <= max){
                printf("%d \n", 1); //print 1 if has converge and break out of loop
                found = 1;
                break;
            }
        }
        if (found == 0){
            printf("%d \n", 0); //print 0 if the loop didnt find any coverage 
        }

        
    }

    

    // free dynamic allocated array 
    free(ROAList);

    // close the file after all processing 
    fclose(fp);
    fclose(tfp);   
    free(pathFromConfig);
    return 0;
}
