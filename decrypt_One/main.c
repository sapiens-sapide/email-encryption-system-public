//
//  main.c
//  decrypt_One
//
//  Created by Stanislas SABATIER on 22/03/2014.
//  Copyright (c) 2014 Stanislas SABATIER. All rights reserved.
//
// démo : à partir d'une biclé préalablement créée et passée en paramètre
// et d'un mail chiffré passé en paramètre
// je sépare la clé AES256 chiffré du reste du message
// je décode la clé AES256 avec la clé privée RSA
// je décode le message chiffré

#include <stdio.h>
#include <unistd.h>
#include <gcrypt.h>
#include <string.h>
#include "../Tools.h"
#include "decipher.h"
#include "../pgsql.h"
#include <syslog.h>
#include <stdarg.h>

#define BUFFLEAP 9216 // 3/4 of emails should fit in 9KB

int main(int argc, const char * argv[])
{
    //2 args expected : user's ID (ie email address) and plain password
    //ciphered email comes in stdin
    
    //INPUTS
    user_t *user;
    char *input, *cipher_email;
    char *ciphered_rsa_priv_key, *cipher_aes_key;
    //OUTPUTS
    header_t *header;
    char *rsa_unlock_key, *aes_plain_key, *email, *rsa_priv_key;
    
    size_t buff_s = BUFFLEAP;
    size_t input_len = 0;
    ssize_t read_len = -1;
    
    int in = fileno(stdin);
    int out = fileno(stdout);
    
    //read the input from stdin
    if (NULL == (input = malloc(BUFFLEAP))) exit(EXIT_FAILURE);
    while (read_len != 0)
    {
        read_len = read(in, input + input_len, buff_s - input_len);
        if (read_len != -1) {
            input_len += read_len;
            if (buff_s - input_len == 0) {   //on est au bout du buffer, il faut l'agrandir.
                buff_s = buff_s*4;
                if (buff_s > BUFFMAX_SIZE) exit(EXIT_FAILURE);
                if (NULL == (input = realloc(input, buff_s))) exit(EXIT_FAILURE);
            }
        } else { //something goes wrong while reading, try to continue with what we got
            break;
        }
    }
    
    if (argc != 3) goto report_error;
    if (NULL ==(user = malloc(sizeof(user_t)))) goto report_error;
    user->email = strdup(argv[1]);
    user->password = strdup(argv[2]);
    //syslog (LOG_INFO|LOG_MAIL, "-> Decrypt arg : %s,%s", user->email,user->password);
    
    if (strcmp(user->password, "n") == 0) { //special case, do nothing
        write(out, input, read_len);
        exit(EXIT_SUCCESS);
    }
    
    //get header
    if (NULL == (header = malloc(sizeof(header_t)))) {
        syslog(LOG_ERR|LOG_MAIL, "[mailden-decrypt-filter] error when alloc for header");
        exit(EXIT_FAILURE);
    }
    if (-1 == parse_header(input, header)) {
        syslog(LOG_ERR|LOG_MAIL, "[mailden-decrypt-filter] error when parsing header");
        exit(EXIT_FAILURE);
    }

    if (header->key_size == 0) { //input is a plain email, do not try to decipher
        write(out, input + HEADER_SIZE + 3 + 8, header->email_size); //just remove mailden's header
        exit(EXIT_SUCCESS);
    }
    
    //get user infos
    if (pgsql_get_userKeys (user) == -1) goto report_error;
    
    //step 0 : get ciphered aes key and ciphered email
    //ciphered aes key
    if (NULL == (cipher_aes_key = malloc(header->key_size))) goto report_error;
    memcpy(cipher_aes_key, input + HEADER_SIZE + 3 + 8 , header->key_size);
    
    //ciphered email
    if (NULL == (cipher_email = malloc(header->email_size))) goto report_error;
    memcpy(cipher_email, input + HEADER_SIZE + 3 + 8 + header->key_size, header->email_size);
    
    libgcrypt_initialize();
    
    //step 1 : decipher private rsa key with user's password + phrase completion
    rsa_unlock_key = build_unlock_key(user->password, user->phrase);
    ciphered_rsa_priv_key = convert_hexstr_to_charstr(user->rsa_priv, strlen(user->rsa_priv));
    if (aes_decipher(ciphered_rsa_priv_key,(strlen(user->rsa_priv)/2)-1, &rsa_priv_key, rsa_unlock_key) == -1) goto report_error;
    
    //step 2 : decipher aes key with private rsa key
    if (rsa_decipher(cipher_aes_key, &aes_plain_key, rsa_priv_key) == -1) goto report_error;
    aes_plain_key = memmove(aes_plain_key, aes_plain_key + 11, 32); //remove first 11 char that don't belong to the key
    
    //step 3 : decipher email
    if (aes_decipher(cipher_email, header->email_size, &email, aes_plain_key) == -1) goto report_error;
    
    //output plain text email
    write(out, email, header->email_size);
    
    exit(EXIT_SUCCESS);
    
report_error:
    if (NULL == (email = malloc(header->email_size))){
        fprintf(stderr, "[mailden-decrypt-filter] error when alloc for error email");
        exit(EXIT_FAILURE);
    }
    
    email = strdup("ERREUR DE DECHIFFRAGE DU EMAIL !! VEUILLEZ CONTACTER LE SUPPORT DE MAILDEN : aide@mailden.net");
    memset (email + 93, ' ',header->email_size - 93); //on complete avec des blancs pour que le email d'erreur ait la meme taille que le email original
    
    //output error email
    write(out, email, header->email_size);
    exit(EXIT_SUCCESS);
}

