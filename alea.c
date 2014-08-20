//
//  alea.c
//  encrypt_One
//
//  Created by Stanislas SABATIER on 24/03/2014.
//  Copyright (c) 2014 Stanislas SABATIER. All rights reserved.
//

#include "alea.h"

#define CHARSET_LENGTH 89

void read_random_device (int size, char *dest)
{
    int fd;
    
    fd = (int) open("/dev/random",O_RDONLY);
    read (fd, dest, size);
}


unsigned char *pick_rand_32bytes (){
    
    typedef struct{
        unsigned int part1;
        unsigned int part2;
        unsigned int part3;
        unsigned int part4;
        char part5[16];
    } CHUNKS;
    
    typedef union
    {
        CHUNKS seed_chunks;
        unsigned char seed[32];
    } MYUNION;
    
    MYUNION u;
    
    srandom((unsigned int)(time(NULL) % 9061973)); // put a secret prime number to raise entropy
    u.seed_chunks.part1 = ((unsigned int)arc4random()%222)+32;
    srandom((unsigned int)(time(NULL) % 2039485230948572951)); // put a secret prime number to raise entropy
    u.seed_chunks.part3 = ((unsigned int)arc4random()%222)+32;
    read_random_device(8, u.seed_chunks.part5);
    srandom((unsigned int)(time(NULL) % 2039485267));  // put a secret prime number to raise entropy
    u.seed_chunks.part2 = ((unsigned int)arc4random()%222)+32;
    srandom((unsigned int)(time(NULL) % 98876033));  // put a secret prime number to raise entropy
    u.seed_chunks.part4 = ((unsigned int)arc4random()%222)+32;
    read_random_device(8, u.seed_chunks.part5 + 8);
    
    unsigned char *aeskey =  gcry_malloc_secure(32);
    memcpy(aeskey, u.seed, 32);
    
    return aeskey;
}

char *pick_rand_16bytes (){
    
    typedef struct{
        unsigned int part1;
        unsigned int part2;
        char part3[8];
    } CHUNKS;
    
    typedef union
    {
        CHUNKS seed_chunks;
        char seed[16];
    } MYUNION;
    
    MYUNION u;
    
    srandom((unsigned int)(time(NULL) % 9887607777782101)); // put a secret prime number to raise entropy
    u.seed_chunks.part1 = (unsigned int)arc4random();
    srandom((unsigned int)(time(NULL) % 98876077793));  // put a secret prime number to raise entropy
    u.seed_chunks.part2 = (unsigned int)arc4random();
    read_random_device(8, u.seed_chunks.part3);
    
    char *key =  gcry_malloc_secure(16);
    memcpy(key, u.seed, 16);
    
    return key;
}

char *random_string (size_t length) {
    
    //static char charset[] = "%*msIMNO@PJKLQtuvwxyz<abc,.-#defghijkl>ABCD_|EUVWXYZ=/01289?34FGHRST5nopqr67!";
    static char charset[] = "%*msIMNOPJ_KLQtuvw@&xyz<abc,.-#de<>{}[DE]fghi(jkl>A)BCUVWXYZ=/012?!89?34FGHRST5n~opqr67!$";
    char *randomString = NULL;
    
    srand(clock()+(time(0)/3001));  //a secret prime number to raise entropy
    int i;
    
    if (length) {
        if (NULL == (randomString = malloc(length +1))) exit(EXIT_FAILURE);
        
        if (randomString) {
            int key = 0;  // one-time instantiation (static/global would be even better)
            for (i = 0 ;i < length; i++) {
                key = rand() % CHARSET_LENGTH;   // no instantiation, just assignment, no overhead from sizeof
                randomString[i] = charset[key];
            }
            
            randomString[length] = '\0';
        }
    }
    
    return randomString;
}

unsigned char *random_string2 (size_t length) {
    
    //return length bytes into the range of printable char from 0x20 to 0xEF ie 256-34 = 222 possibilities
    
    unsigned char *randomString = NULL;
    srand(clock()+(time(0)/3011));  // a secret prime number to raise entropy
    int i;
    
    if (length) {
        if (NULL == (randomString = gcry_malloc_secure(length))) return NULL;
        
        if (randomString) {
            unsigned char key = 0;
            for (i = 0 ;i < length; i++) {
                key = (unsigned char)rand();
                randomString[i] = (key % 222) + 33;
            }
        }
    }
    
    return randomString;
}