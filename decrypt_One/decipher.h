//
//  decipher.h
//  encrypt_One
//
// Copyleft (ɔ) 2014 Mailden
// Use of this source code is governed by a GNU AFFERO GENERAL PUBLIC
// license (AGPL) that can be found in the LICENSE file.

#ifndef encrypt_One_decipher_h
#define encrypt_One_decipher_h

#include <gcrypt.h>
#include "../alea.h"
#include "../Tools.h"

int aes_decipher(char *input, size_t input_len, char **output, const char *key);

int rsa_decipher(char *input, char **output, const char *key);

#endif
