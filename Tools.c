//
//  Tools.c
//  encrypt_One
//
//  Created by Stanislas SABATIER on 23/03/2014.
//  Copyright (c) 2014 Stanislas SABATIER. All rights reserved.
//

#include "Tools.h"
#include <syslog.h>
#include <stdarg.h>

void libgcrypt_initialize (void) {
    // library initialization
    /* Version check should be the very first call because it
     makes sure that important subsystems are initialized. */
    if (!gcry_check_version (GCRYPT_VERSION))
    {
        fputs ("libgcrypt version mismatch\n", stderr);
        exit (2);
    }
    /* We don’t want to see any warnings, e.g. because we have not yet
     parsed program options which might be used to suppress such
     warnings. */
    gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);
    /* ... If required, other initialization goes here.  Note that the
     process might still be running with increased privileges and that
     the secure memory has not been initialized.  */
    /* Allocate a pool of 64k secure memory.  This make the secure memory
     available and also drops privileges where needed.  */
    gcry_control (GCRYCTL_INIT_SECMEM, 65536, 0);
    /* It is now okay to let Libgcrypt complain when there was/is
     a problem with the secure memory. */
    //gcry_control (GCRYCTL_RESUME_SECMEM_WARN);
    /* ... If required, other initialization goes here.  */
    /* Tell Libgcrypt that initialization has completed. */
    gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
    
    if (!gcry_control (GCRYCTL_INITIALIZATION_FINISHED_P))
    {
        fputs ("libgcrypt has not been initialized\n", stderr);
        abort ();
    }
    
}

void die (char *str){
    fprintf( stderr, "[ERROR] %s\n",str );
    exit(EXIT_FAILURE);
}

void charTosexp (const unsigned char *plain, gcry_sexp_t *s_exp){
    
    if( gcry_sexp_build(s_exp, NULL, "(data(flags pkcs1)(value %s))", plain ) ) die( " during mpi->s-expression conversion." );
    return;
}

size_t outputSexp (gcry_sexp_t s_exp, char **txtexp){
    
    size_t length;
    length = gcry_sexp_sprint(s_exp, GCRYSEXP_FMT_CANON, NULL, MAX_BUFF_SIZE);
    *txtexp = malloc(length);
    if( gcry_sexp_sprint( s_exp, GCRYSEXP_FMT_CANON, *txtexp, length ) == 0 ) die( " during s-exp export" );
    
    return length;
}

/* Convert LENGTH bytes of data in CHAR_STRING into hex encoding and store
 that in HEX_STRING.  HEX_STRING must be allocated of at
 least (2*LENGTH+1) bytes or be NULL so that the function mallocs an
 appropriate buffer.  Returns HEX_STRING or NULL on error (which may
 only occur if HEX_STRING has been NULL and the internal malloc
 failed). */
char *convert_char_to_hexstring (const void *char_string, size_t length, char *hex_string){
    const unsigned char *s;
    char *p;
    
    if (!hex_string)
    {
        size_t nbytes = 2 * length + 1;
        if (length &&  (nbytes-1) / 2 != length)
        {
            errno = ENOMEM;
            return 0;
        }
        hex_string = gcry_malloc_secure(nbytes);
        if (!hex_string)
            return 0;
    }
    
    for (s = char_string, p = hex_string; length; length--, s++)
    {
        *p++ = tohex ((*s>>4)&15);
        *p++ = tohex (*s&15);
    }
    *p = 0;

    return hex_string;
}

/* Convert STRING consisting of hex characters into its binary
 representation and store that at BUFFER.  BUFFER needs to be of
 LENGTH bytes.  The function returns -1 on
 error or the length of the parsed string.  */
int convert_hexstring_to_char (const char *hex_string, size_t length, void *char_string)
{
    int i;
    const char *s = hex_string;
    char_string = malloc(length);
    char *p;
    p = malloc(length);
    for (i=0; i < length; )
    {
        if (!hexdigitp (s) || !hexdigitp (s+1)) return -1;           /* Invalid hex digits. */
        ((unsigned char*)char_string)[i++] = xtoi_2 (s);
        p[i++] = xtoi_2 (s);
        s += 2;
    }
    if (*s && (!isascii (*s) || !isspace (*s)) ) return -1;             /* Not followed by Nul or white space.  */
    if (i != length) return -1;             /* Not of expected length.  */
    if (*s) s++; /* Skip the delimiter. */
    return (int)(s - hex_string);
}

char *convert_hexstr_to_charstr (const char *hex_string, size_t length){
    int number;
    int i, j;
    
    char *char_string;
    if (NULL == (char_string = malloc(length / 2))) exit(EXIT_FAILURE);
    
    for (i = 0, j = 0; i < length; i+=2, j++) {
        sscanf(&hex_string[i], "%02x", &number);
        char_string[j] = (char)number;
    }
    
    return char_string;
}

char *build_unlock_key (const char *user_pass, const char *phrase_completion){
    char *key;
    size_t pass_length = strlen(user_pass);
    
    key = gcry_malloc_secure(33);
    memccpy(key, user_pass, sizeof(char), pass_length);
    memccpy(key + pass_length, phrase_completion + pass_length, sizeof(char), 32 - pass_length);
    key[32] = '\0';
    return key;
}

int parse_header(char *input, header_t *header){
    
    char *key_size_str[4];
    char *email_len_str[9];
    
    //check if we have a canonical mailden header
    char beginning[10];
    memcpy(beginning, input, 10);
    if (NULL == strstr(input, "##mailden-")) {
        syslog(LOG_ERR|LOG_MAIL, "Error when parsing header : ##mailden- NOT FOUND");
        return -1;
    }
    
    if (NULL == memcpy(header->version, input + 10, 8)) return -1;
    header->version[8] = '\0';
    
    if (NULL == memcpy(key_size_str, input + HEADER_SIZE, 3)) return -1;
    key_size_str[3] = '\0';
    header->key_size = strtoul(key_size_str, NULL, 10);
    
    if (NULL == memcpy(email_len_str, input + HEADER_SIZE + 3, 8)) return -1;
    email_len_str[8] = '\0';
    header->email_size = strtoul(email_len_str, NULL, 10);
    
    return 1;
}