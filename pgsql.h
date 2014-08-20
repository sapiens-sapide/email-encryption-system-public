//
//  pgsql.h
//  encrypt_One
//
//  Created by Stanislas SABATIER on 11/05/2014.
//  Copyright (c) 2014 Stanislas SABATIER. All rights reserved.
//

#ifndef encrypt_One_pgsql_h
#define encrypt_One_pgsql_h

#include "../include/libpq-fe.h"
#include "chaines.h"

#define CONNEXION_PARAMS pg_connexion("127.0.0.1","mail","pgsql",NULL)

typedef struct {
    char *email;
    char *password;
    char *phrase;
    char *rsa_priv;
} user_t;

typedef struct {
    char *email;
    char *name;
    string_t *maildir;
    char *passphrase;
    string_t *pwd;
    char *rsapub;
    char *rsapriv_crypt;
    char *days;
} newUser_t;

PGconn *pg_connexion(const char *serveur, const char *db, const char *user, const char *pwd);
int     pgsql_get_rsaPubKey(char *email, char **rsa_pub_key, char *do_crypt);
int     pgsql_get_userKeys(user_t *user);
int     pg_creer_utilisateur (newUser_t *user);
int     pg_requete_simple (PGconn * pgh, const char *requete);
int     pg_creer_alias (char *email);
int     pg_update_pass (char *email, char *new_hash, char *new_ciphered_rsa_priv_key, char *prev_ciphered_rsa_priv_key);
#endif
