//
//  Tools.h
//  encrypt_One
//
//  Created by Stanislas SABATIER on 24/03/2014.
//  Copyright (c) 2014 Stanislas SABATIER. All rights reserved.
//


#include <stdio.h>
#include <gcrypt.h>
#include <assert.h>
#include <errno.h>
#include <ctype.h>


#ifndef encrypt_One_Tools_h
#define encrypt_One_Tools_h

#define MAX_BUFF_SIZE 4096
#define tohex(n) ((n) < 10 ? ((n) + '0') : (((n) - 10) + 'A'))
#define digitp(p)   (*(p) >= '0' && *(p) <= '9')
#define hexdigitp(a) (digitp (a) || (*(a) >= 'A' && *(a) <= 'F') || (*(a) >= 'a' && *(a) <= 'f'))
/* The atoi macros assume that the buffer has only valid digits. */
#define atoi_1(p)   (*(p) - '0' )
#define atoi_2(p)   ((atoi_1(p) * 10) + atoi_1((p)+1))
#define xtoi_1(p)   (*(p) <= '9'? (*(p)- '0'): *(p) <= 'F'? (*(p)-'A'+10):(*(p)-'a'+10))
#define xtoi_2(p)   ((xtoi_1(p) * 16) + xtoi_1((p)+1))

#define HEADER_SIZE 20
/* Maximum buffer size in bytes - do not allow it to grow larger than this. */
#define	BUFFMAX_SIZE 37748736 // ~20Mo = max authorized email size at postfix's gate

typedef struct {
    char version[9];
    size_t key_size;
    size_t email_size;
} header_t;

void libgcrypt_initialize (void);

void die(char *str);

void charTosexp(const unsigned char *plain, gcry_sexp_t *s_exp);

size_t outputSexp (gcry_sexp_t s_exp, char **txtexp);

char *convert_char_to_hexstring (const void *char_string, size_t length, char *hex_string);

int convert_hexstring_to_char (const char *hex_string, size_t length, void *char_string);
char *convert_hexstr_to_charstr (const char *hex_string, size_t length);

char *build_unlock_key (const char *user_pass, const char *phrase_completion);

int parse_header(char *input, header_t *header);

#endif
