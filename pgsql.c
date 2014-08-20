//
//  pgsql.c
//  encrypt_One
//
//  Created by Stanislas SABATIER on 11/05/2014.
//  Copyright (c) 2014 Stanislas SABATIER. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include "pgsql.h"

PGconn *pg_connexion(const char *serveur, const char *db, const char *user, const char *pwd) {
    PGconn *pgh;
    
    /* connexion a la base */
    pgh = PQsetdbLogin(serveur, NULL, NULL, NULL, db, user, pwd);
    if (PQstatus(pgh) != CONNECTION_OK) {
        fprintf(stderr, "[mailden-filter] echec de la connexion a la db %s\n",db);
        fprintf(stderr, "%s",PQerrorMessage(pgh));
        PQfinish(pgh);
        return NULL;
    }
    return pgh;
}

int pg_requete_simple (PGconn * pgh, const char *requete) {
    PGresult *pgr;
    ExecStatusType status;
    
    /* Requete au serveur. */
    pgr = PQexec (pgh, requete);
    
    /* Obtention de l'etat de la requete pour tester si une erreur
     * est survenue.
     */
    status = PQresultStatus (pgr);
    if (PGRES_COMMAND_OK != status)
    {
        char *s;
        fprintf (stderr, "Échec : '%s' %s\n", requete, ((s = PQcmdStatus (pgr)) ? s : "OK"));
        PQfinish (pgh);
        return (-1);
    }
    
    /* Liberation des espaces memoire alloues pour la requete,
     * dans le programme ainsi que dans la base.
     */
    PQclear (pgr);
    return (0);
}


int pgsql_get_rsaPubKey(char *email, char **rsa_pub_key, char *do_crypt) {
    
    PGconn *connexion;
    
    if ((connexion = CONNEXION_PARAMS) == NULL) {
        do_crypt = strdup("f");
        rsa_pub_key = NULL;
        return 0;
    }
    
    PGresult *pgr;
    string_t *requete;
    string_t *esc;
    ExecStatusType status;
    char *s;
    int l;
    
    /* Requete SQL, obtention de l'etat et test d'erreur. */
    requete = string_new();
    esc = string_new();
    string_ajout(requete, "SELECT rsapub,do_crypt FROM users where email = '");
    string_pg_escape (esc, email);
    string_ajout(requete, esc->str);
    string_ajout(requete, "'");
    
    pgr = PQexec (connexion, requete->str);
    status = PQresultStatus (pgr);
    if (PGRES_TUPLES_OK != status)
    {
        fprintf (stderr, "echec de la requete (%s)\n", ((s = PQcmdStatus (pgr)) ? s : "OK"));
        PQfinish (connexion);
        *do_crypt = 'f';
        rsa_pub_key = NULL;
        return 0;
    }
    /* Obtention du nombre de lignes
     */
    l = PQntuples (pgr);
    switch (l) {
        case 0:
            fprintf (stderr, "[mailden-filter] L'adresse email est introuvable");
            *do_crypt = 'f';
            rsa_pub_key = NULL;
            return 0;
            break;
            
        case 1:
            break;
            
        default:
            fprintf (stderr, "[mailden-filter] echec de la requete pgsql, + de 1 resultat !");
            *do_crypt = 'f';
            rsa_pub_key = NULL;
            return 0;
            break;
    }
    
    *rsa_pub_key = strdup(PQgetvalue (pgr, 0, 0));
    *do_crypt = *PQgetvalue (pgr, 0, 1);
    PQclear (pgr);
    PQfinish(connexion);
    return 1;
}

int pgsql_get_userKeys(user_t *user) {
    PGconn *connexion;
    if ((connexion = CONNEXION_PARAMS) == NULL){
        return -1;
    }
    
    PGresult *pgr;
    string_t *requete;
    string_t *esc;
    ExecStatusType status;
    char *s;
    int l;
    
    /* Requete SQL, obtention de l'etat et test d'erreur. */
    requete = string_new();
    esc = string_new();
    string_ajout(requete, "SELECT passphrase, rsapriv FROM users where email = '");
    string_pg_escape (esc, user->email);
    string_ajout(requete, esc->str);
    string_ajout(requete, "'");
    
    pgr = PQexec (connexion, requete->str);
    status = PQresultStatus (pgr);
    if (PGRES_TUPLES_OK != status)
    {
        fprintf (stderr, "echec de la requete pgsql (%s)\n", ((s = PQcmdStatus (pgr)) ? s : "OK"));
        PQfinish (connexion);
        return -1;
    }
    /* Obtention du nombre de lignes
     */
    l = PQntuples (pgr);
    switch (l) {
        case 0:
            fprintf (stderr, "[mailden-db] L'adresse email est introuvable");
            return -1;
            
        case 1:
            break;
            
        default:
            fprintf (stderr, "[mailden-db] echec de la requete pgsql, %i resultats !", l);
            return -1;
    }
    
    user->phrase = strdup(PQgetvalue (pgr, 0, 0));
    user->rsa_priv = strdup(PQgetvalue(pgr, 0, 1));
    PQclear (pgr);
    PQfinish(connexion);
    return 1;
}

int pg_creer_utilisateur (newUser_t *user) {
    
    PGconn *connexion;
    
    if ((connexion = CONNEXION_PARAMS) == NULL) return -1;
    
    char *str;
    PGresult *pgr;
    ExecStatusType status;
    int l;
    int r;
    
    /* Test si l'utilisateur n'existe pas deja. */
    str = malloc (sizeof ("SELECT email FROM users WHERE email='*'") + strlen (user->email));
    sprintf (str, "SELECT email FROM users WHERE email='%s'", user->email);
    
    pgr = PQexec (connexion, str);
    free (str);
    status = PQresultStatus (pgr);
    if (PGRES_TUPLES_OK != status)
    {
        fprintf (stderr, "Échec de la requête (%s)\n", ((str = PQcmdStatus (pgr)) ? str : "OK"));
        PQfinish (connexion);
        return -1;
    }
    /* Obtention du nombre de lignes.
     * S'il est nul, l'utilisateur n'existe pas.
     */
    l = PQntuples (pgr);
    if (0 != l)
    {
        fprintf (stderr, "L'utilisateur existe déjà");
        PQfinish (connexion);
        return -1;
    }
    
    /* Création de l'utilisateur. */
    str = malloc (sizeof ("INSERT INTO users VALUES ('*','*','*','*','*','*','*',DEFAULT,'t','t',current_date + interval ' days')") + strlen (user->email) + strlen (user->name) + user->maildir->len + user->pwd->len + strlen (user->passphrase) + strlen (user->rsapub) + strlen (user->rsapriv_crypt) + strlen(user->days));
    sprintf (str, "INSERT INTO users VALUES ('%s','%s','%s','%s','%s','%s','%s',DEFAULT,'t','t',current_date + interval '%s days')", user->email, user->name, user->maildir->str, user->pwd->str, user->passphrase, user->rsapub, user->rsapriv_crypt, user->days);
    
    r = pg_requete_simple (connexion, str);
    free (str);
    return (r);
}

int pg_creer_alias (char *email) {
    PGconn *connexion;
    
    if ((connexion = CONNEXION_PARAMS) == NULL) return -1;
    
    char *str;
    PGresult *pgr;
    ExecStatusType status;
    int l;
    int r;
    
    /* Test si l'alias n'existe pas deja. */
    str = malloc (sizeof ("SELECT alias FROM aliases WHERE alias='*'") + strlen (email));
    sprintf (str, "SELECT alias FROM aliases WHERE email='%s'", email);
    
    pgr = PQexec (connexion, str);
    free (str);
    status = PQresultStatus (pgr);
    if (PGRES_TUPLES_OK != status)
    {
        fprintf (stderr, "Échec de la requête (%s)\n", ((str = PQcmdStatus (pgr)) ? str : "OK"));
        PQfinish (connexion);
        return -1;
    }
    /* Obtention du nombre de lignes.
     * S'il est nul, l'utilisateur n'existe pas.
     */
    l = PQntuples (pgr);
    if (0 != l)
    {
        printf ("L'alias existe déjà");
        PQfinish (connexion);
        return -1;
    }
    
    /* Création de l'alias. */
    str = malloc (sizeof ("INSERT INTO aliases VALUES ('*','*')") + (strlen (email) * 2));
    sprintf (str, "INSERT INTO aliases VALUES ('%s','%s')", email, email);
    
    r = pg_requete_simple (connexion, str);
    free (str);
    return (r);
}

int pg_update_pass (char *email, char *new_hash, char *new_ciphered_rsa_priv_key, char *prev_ciphered_rsa_priv_key) {
    PGconn *connexion;
    
    if ((connexion = CONNEXION_PARAMS) == NULL) return -1;
    
    char *str;
    int r;
    
    asprintf (&str, "UPDATE users SET password='%s', rsapriv='%s', old_rsa='%s' WHERE email='%s'", new_hash, new_ciphered_rsa_priv_key, prev_ciphered_rsa_priv_key, email);
    
    r = pg_requete_simple (connexion, str);
    free (str);
    return (r);
}
