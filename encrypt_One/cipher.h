//
//  cipher.h
//  encrypt_One
//
//  Created by Stanislas SABATIER on 24/03/2014.
//  Copyright (c) 2014 Stanislas SABATIER. All rights reserved.
//

#ifndef encrypt_One_cipher_h
#define encrypt_One_cipher_h

#include <gcrypt.h>
#include "../alea.h"
#include "../Tools.h"

int aes_cipher(char *input, size_t input_len, char **output, const unsigned char *key);
size_t rsa_cipher(const unsigned char *input, char **output, const char *key);

#endif
