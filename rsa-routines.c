//
//  rsa-routines.c
//  encrypt_One
//
//  Created by Stanislas SABATIER on 10/04/2014.
//  Copyright (c) 2014 Stanislas SABATIER. All rights reserved.
//

#include "rsa-routines.h"

void gcry_to_clean_char (const gcry_sexp_t *sexp, char **char_exp){
    size_t length;
    int i;
    int j = 0;
    char *tmp, *tmp2;
    length = gcry_sexp_sprint(*sexp, GCRYSEXP_FMT_ADVANCED, NULL, MAX_BUFF_SIZE);
    tmp = malloc(length);
    tmp2 = *char_exp = malloc(length);
    
    if( gcry_sexp_sprint(*sexp, GCRYSEXP_FMT_ADVANCED, tmp, length) == 0)
        /*die( " during s-exp export" )*/;
    
    for (i = 0; i < length; i++) {
        if (tmp[i] != '\n' && tmp[i] != ' ') {
            tmp2[j] = tmp[i];
            j++;
        }
    }
    
    *char_exp = strdup(tmp2);
    free(tmp);
    free(tmp2);
}

void generate_rsa_keypair (char **rsapub, char **rsapriv) {
    
    
    gcry_sexp_t key_spec, key, pub_key, sec_key;
    int rc;
    
    rc = gcry_sexp_new( &key_spec, "(genkey (rsa (nbits 4:4096)))",0,1);
    //if( rc ) die( "error creating S-expression." );
    
    rc = gcry_pk_genkey( &key, key_spec );
    gcry_sexp_release( key_spec );
    //if( rc ) die( "error generating RSA key." );
    
    pub_key = gcry_sexp_find_token( key, "public-key", 0 );
    //if ( !pub_key ) die( "public part missing in key." );
    
    sec_key = gcry_sexp_find_token( key, "private-key", 0 );
    //if ( !sec_key ) die( "private part missing in key." );
    
    gcry_sexp_release(key);
    
    gcry_to_clean_char(&pub_key, rsapub);
    gcry_to_clean_char(&sec_key, rsapriv);
        
}