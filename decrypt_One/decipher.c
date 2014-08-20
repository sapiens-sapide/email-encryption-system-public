//
//  decipher.c
//  encrypt_One
//
//  Created by Stanislas SABATIER on 24/03/2014.
//  Copyright (c) 2014 Stanislas SABATIER. All rights reserved.
//

#include "decipher.h"

int aes_decipher(char *input, size_t input_len, char **output, const char *key){
    
#define KEY_LENGTH 32
#define BLOCK_LENGTH 16
    
    gcry_error_t gcryError;
    gcry_cipher_hd_t gcryCipherHd;
    char iniVector[16];
    
    memcpy(iniVector, key, 16); // the first 16 bytes of aes key
    size_t txtLength = input_len + 1;     // string length plus termination
    
    if (NULL == (*output = gcry_malloc(txtLength))) {
        fprintf(stderr, "[mailden-filter decrypt] Error when allocating memory in aes_decipher function");
        return -1;
    }
    
    gcryError = gcry_cipher_open(&gcryCipherHd, GCRY_CIPHER_RIJNDAEL256, GCRY_CIPHER_MODE_CFB, 0);
    
    if (gcryError)
    {
        fprintf(stderr, "[mailden-filter decrypt] gcry_cipher_open failed:  %s/%s\n", gcry_strsource(gcryError), gcry_strerror(gcryError));
        return -1;
    }
    
    gcryError = gcry_cipher_setkey(gcryCipherHd, key, KEY_LENGTH);
    if (gcryError)
    {
        fprintf(stderr, "[mailden-filter decrypt] gcry_cipher_setkey failed:  %s/%s\n", gcry_strsource(gcryError), gcry_strerror(gcryError));
        return -1;
    }
    
    gcryError = gcry_cipher_setiv(gcryCipherHd, iniVector, BLOCK_LENGTH);
    if (gcryError)
    {
        fprintf(stderr, "[mailden-filter decrypt] gcry_cipher_setiv failed:  %s/%s\n", gcry_strsource(gcryError), gcry_strerror(gcryError));
        return -1;
    }
    
    gcryError = gcry_cipher_decrypt(gcryCipherHd, *output, txtLength, input, txtLength);
    if (gcryError)
    {
        fprintf(stderr, "[mailden-filter decrypt] gcry_cipher_encrypt failed:  %s/%s\n", gcry_strsource(gcryError), gcry_strerror(gcryError));
        return -1;
    }
    
    // clean up after ourselves
    gcry_cipher_close(gcryCipherHd);
    return 1;
    
}

int rsa_decipher(char *input, char **output, const char *key){
    
    gcry_sexp_t p_key_sexp, input_sexp, out_sexp;
    size_t key_len;
    gcry_error_t gcryError;
    
    //Import strings into s-expressions
    gcryError = gcry_sexp_new(&p_key_sexp, key, 0, 1);
    if (gcryError) {
        fprintf(stderr, "[mailden-filter decrypt] Error during private rsa key import : %s/%s\n", gcry_strsource(gcryError), gcry_strerror(gcryError));
        return -1;
    }
    
    key_len = gcry_sexp_canon_len(input, 0, NULL, NULL);
    if (gcry_sexp_new(&input_sexp, input, key_len, 1)) {
        fprintf(stderr, "[mailden-filter decrypt] Error during ciphered aes key import.");
        return -1;
    }
    
    gcry_sexp_t temp;
    temp = gcry_sexp_find_token(input_sexp,"rsa",0);
    if (gcry_sexp_build(&input_sexp, NULL, "(enc-val(flags pkcs1)%S)", temp)) {
        fprintf(stderr, "[mailden-filter decrypt] Error during ciphered aes key import.");
        return -1;
    }
    
    gcryError = gcry_pk_decrypt(&out_sexp, input_sexp, p_key_sexp);
    if (gcryError) {
        fprintf(stderr, "[mailden-filter decrypt] Error during the rsa decryption phase : %s/%s\n", gcry_strsource(gcryError), gcry_strerror(gcryError));
        return -1;
    }
    
    outputSexp(out_sexp, output);
    
    //cleanup
    gcry_sexp_release(temp);
    gcry_sexp_release(input_sexp);
    gcry_sexp_release(p_key_sexp);
    gcry_sexp_release(out_sexp);
    return 1;
}
