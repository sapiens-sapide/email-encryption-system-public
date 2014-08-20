//
//  main.c
//  CreateUser
//
//  Created by Stanislas SABATIER on 16/05/2014.
//  Copyright (c) 2014 Stanislas SABATIER. All rights reserved.
//

#include <stdlib.h>
#include <stdio.h>
#include <gcrypt.h>
#include <assert.h>
#include <string.h>
#include "../alea.h"
#include "../pgsql.h"
#include "../rsa-routines.h"
#include "../crypt_blowfish-1.1/ow-crypt.h"
#include "../Tools.h"
#include "../encrypt_One/cipher.h"
#include <syslog.h>


void cipher_key (const char *key_to_cipher, const char *aes_key, char **hex_output) {
    
    char *output;
    int l;
    l = strlen(key_to_cipher);
    aes_cipher(key_to_cipher, l, &output, aes_key);
    
    *hex_output = malloc(l*2);
    convert_char_to_hexstring(output, l, *hex_output);
}

int main(int argc, const char * argv[])
{
    //expect 4 args : email, user name, plain password (10 to 20 chars), days. String controls have been made before calling this program.
    if (argc != 5) exit(EXIT_FAILURE);
    
    newUser_t *user;
    char *local;
    char *rsapriv;
    char rsapriv_key[33];
    size_t pwd_size;
    
    user = malloc(sizeof(newUser_t));
    user->email = strdup(argv[1]);
    user->name = strdup(argv[2]);
    user->days = strdup(argv[4]);

    
    //passphrase & aeskey
    pwd_size = strlen(argv[3]);
    if ( pwd_size < 10 || pwd_size > 20 ) {
        fprintf(stderr, "incorrect password length : %zu chars.", pwd_size);
        exit(EXIT_FAILURE);
    }
    user->passphrase = random_string(32);
    memcpy(rsapriv_key, argv[3], pwd_size);
    memcpy(rsapriv_key + pwd_size, user->passphrase + pwd_size, 32 - pwd_size);
    rsapriv_key[32] = '\0';
    
    libgcrypt_initialize();
    
    //rsa keys
    generate_rsa_keypair( &user->rsapub, &rsapriv);
    cipher_key(rsapriv, rsapriv_key, &user->rsapriv_crypt);
   
    //hash password
    char *settings;
    settings = crypt_gensalt_ra("$2a$", 7, random_string(16), 16);
    user->pwd = string_new();
    string_ajout(user->pwd, "{BLF-CRYPT}");
    string_ajout(user->pwd, crypt(argv[3], settings));

    //build maildir string
    user->maildir = string_new();
    string_ajout(user->maildir, "/");
    local = strtok(strdup(argv[1]), "@");
    string_ajout(user->maildir, strtok(NULL, "@"));
    string_ajout(user->maildir, "/");
    string_ajout(user->maildir, local);
    string_ajout(user->maildir, "/");
    
    //insert user in 2 tables : users & aliases
    if (pg_creer_utilisateur(user) != -1) {
        printf("OK 1/2 : Utilisateur ajouté dans la table users.\n");
        if (pg_creer_alias(user->email) != -1) {
            printf("OK 2/2 : Alias créé.\n");
         } else {
            fprintf(stderr, "Erreur lors de la création de l'alias.");
            exit(EXIT_FAILURE);
        }
    } else {
        fprintf(stderr, "Erreur lors de l'insertion de l'utilisateur dans la base users.");
        exit(EXIT_FAILURE);
    }
    
    exit(EXIT_SUCCESS);
}

