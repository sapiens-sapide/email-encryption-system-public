//
//  alea.h
//  encrypt_One
//
// Copyleft (ɔ) 2014 Mailden
// Use of this source code is governed by a GNU AFFERO GENERAL PUBLIC
// license (AGPL) that can be found in the LICENSE file.

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
