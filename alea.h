//
//  alea.h
//  encrypt_One
//
//  Created by Stanislas SABATIER on 24/03/2014.
//  Copyright (c) 2014 Stanislas SABATIER. All rights reserved.
//

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <gcrypt.h>
#include <stdio.h>

#ifndef encrypt_One_alea_h
#define encrypt_One_alea_h

unsigned char *pick_rand_32bytes ();
char *pick_rand_16bytes ();
char *random_string (size_t length);
unsigned char *random_string2 (size_t length);

#endif
