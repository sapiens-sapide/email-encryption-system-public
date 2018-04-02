//
//  cipher.h
//  encrypt_One
//
// Copyleft (ɔ) 2014 Mailden
// Use of this source code is governed by a GNU AFFERO GENERAL PUBLIC
// license (AGPL) that can be found in the LICENSE file.

#ifndef encrypt_One_cipher_h
#define encrypt_One_cipher_h

#include <gcrypt.h>
#include "../alea.h"
#include "../Tools.h"

int aes_cipher(char *input, size_t input_len, char **output, const unsigned char *key);
size_t rsa_cipher(const unsigned char *input, char **output, const char *key);

#endif
