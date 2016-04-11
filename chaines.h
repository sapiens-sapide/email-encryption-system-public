//edition
//  chaines.h
//  postgre primer
//
//  Created by Stanislas SABATIER on 11/05/2014.
//  Copyright (c) 2014 Stanislas SABATIER. All rights reserved.
//

#ifndef postgre_primer_chaines_h
#define postgre_primer_chaines_h

#include <string.h>

/* type plus pratique que char* pour la gestion des chaines */
typedef struct
{
    char *str;                    /* Chaine */
    size_t size;                     /* Taille de l'espace alloue */
    size_t len;                      /* Longueur de la chaine */
} string_t;

#define STRING_BLOCK_SIZE 1024

string_t *string_new (void);
string_t *string_new_initial_len (void);
void string_free (string_t * str);
void string_ajout (string_t *str, const char *str2);
void string_pg_escape (string_t * str, const char *str2);

#endif
