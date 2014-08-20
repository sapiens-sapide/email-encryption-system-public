//
//  chaines.c
//  postgre primer
//
//  Created by Stanislas SABATIER on 11/05/2014.
//  Copyright (c) 2014 Stanislas SABATIER. All rights reserved.
//

#include "chaines.h"
#include <stdlib.h>

/* Allocation de memoire pour une nouvelle chaine, vide.
 */
string_t *string_new (void)
{
    string_t *s;
    if (NULL != (s = malloc (sizeof *s)))
    {
        s->str = NULL;
        s->size = 0;
        s->len = 0;
    }
    return (s);
}

/* Allocation de memoire pour une nouvelle chaine,
 * avec pre-allocation d'un bloc de memoire.
 * La chaine est vide.
 */
string_t *string_new_initial_len (void)
{
    string_t *str;
    if (NULL != (str = malloc (sizeof *str)))
    {
        str->str = malloc (STRING_BLOCK_SIZE * sizeof *str->str);
        str->size = STRING_BLOCK_SIZE;
        str->len = 0;
    }
    return (str);
}

/* Liberation de la memoire allouee pour une chaine
 */
void string_free (string_t * str)
{
    if (str)
    {
        if (str->str)
            free (str->str);
        free (str);
    }
}

/* Concatenation d'une chaine char* a une chaine string_t */
/* Note : pour concatener deux chaines string_t, faire
 * string_ajout(resultat, chaine->str);
 */
void string_ajout (string_t *str, const char *str2)
{
    size_t l;
    l = strlen (str2);
    if (str->size < (str->len + l + 1))
    {
        str->size = (1 + (str->size + l + 1) / STRING_BLOCK_SIZE) * STRING_BLOCK_SIZE;
        str->str = realloc (str->str, str->size * sizeof (*str->str));
    }
    memcpy (str->str + str->len, str2, l + 1);
    str->len += l;
}

/* Cette fonction fait appel à PQescapeString() pour filtrer
 * les chaines qui viennent de l'utilisateur et pour echapper les caracteres.
 */

void string_pg_escape (string_t * str, const char *str2) {
    size_t l;
    l = strlen (str2);
    if (str->size < 2 * l)
    {
        str->size = (1 + (2 * l / STRING_BLOCK_SIZE))
        * STRING_BLOCK_SIZE;
        str->str = realloc (str->str, str->size * sizeof *str->str);
    }
    str->len = PQescapeString (str->str, str2, str->size);
}
