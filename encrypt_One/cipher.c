//
//  cipher.c
//  encrypt_One
//
//  Created by Stanislas SABATIER on 24/03/2014.
//  Copyright (c) 2014 Stanislas SABATIER. All rights reserved.
//

#include <stdio.h>
#include "cipher.h"
#include <wchar.h>

int aes_cipher(char *input, size_t input_len, char **output, const unsigned char *key) {
    
#define KEY_LENGTH 32
#define BLOCK_LENGTH 16
    
    gcry_error_t     gcryError;
    gcry_cipher_hd_t gcryCipherHd;
    char iniVector[16];

    memcpy(iniVector, key, 16); // the first 16 bytes of aes key
    size_t txtLength = input_len + 1;     // string length plus termination
    
    *output = malloc(txtLength);
    
    gcryError = gcry_cipher_open(&gcryCipherHd, GCRY_CIPHER_RIJNDAEL256, GCRY_CIPHER_MODE_CFB, 0);
    
    if (gcryError) {
        fprintf(stderr, "gcry_cipher_open failed:  %s/%s\n", gcry_strsource(gcryError), gcry_strerror(gcryError));
        return -1;
    }
    
    gcryError = gcry_cipher_setkey(gcryCipherHd, key, KEY_LENGTH);
    if (gcryError) {
        fprintf(stderr, "gcry_cipher_setkey failed:  %s/%s\n", gcry_strsource(gcryError), gcry_strerror(gcryError));
        return -1;
    }
    
    gcryError = gcry_cipher_setiv(gcryCipherHd, iniVector, BLOCK_LENGTH);
    if (gcryError) {
        fprintf(stderr, "gcry_cipher_setiv failed:  %s/%s\n", gcry_strsource(gcryError), gcry_strerror(gcryError));
        return -1;
    }
    
    gcryError = gcry_cipher_encrypt(gcryCipherHd, *output, txtLength, input, txtLength);
    if (gcryError) {
        fprintf(stderr, "gcry_cipher_encrypt failed:  %s/%s\n", gcry_strsource(gcryError), gcry_strerror(gcryError));
        return -1;
    }
    
    // clean up after ourselves
    gcry_cipher_close(gcryCipherHd);
    return 1;
}

size_t rsa_cipher(const unsigned char *input, char **output, const char *key) {
    
    gcry_sexp_t p_key_sexp, input_sexp, crypt_sexp;
    int err;
    
    //Import strings into s-expressions
    charTosexp(input, &input_sexp );
    if (gcry_sexp_new(&p_key_sexp, key, 0, 1)){
        fprintf(stderr, "[mailden-filter] Error during public rsa key import.");
        return -1;
    }
    
    if ((err = gcry_pk_encrypt(&crypt_sexp, input_sexp, p_key_sexp))){
        fprintf(stderr, "[mailden-filter] Error during the rsa encryption phase.");
        return -1;
    }
    
    return outputSexp(crypt_sexp, output);
}