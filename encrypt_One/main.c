//
//  main.c
//  encrypt_One
//
// Copyleft (ɔ) 2014 Mailden
// Use of this source code is governed by a GNU AFFERO GENERAL PUBLIC
// license (AGPL) that can be found in the LICENSE file.


#include <stdio.h>
#include <unistd.h>
#include <gcrypt.h>
#include "../Tools.h"
#include "../alea.h"
#include "cipher.h"
#include "../pgsql.h"
#include <syslog.h>
#include <stdarg.h>

#define BUFFLEAP 9216 // 3/4 of emails should fit in 9KB
#define VERSION "##mailden-01.06.00##"

int main(int argc, const char * argv[])
{
    //1 arg expected : user's ID (ie email address)
    //plain email comes in stdin
    
    ////INITS////
    char *email;
    char *user_id;
    unsigned char *aes_plain_key;
    char *cipher_email, *cipher_aes_key, *output;
    char *rsa_pub_key;
    char do_crypt='f';
    const char *header = VERSION;
    char key_size_str[4];
    char input_len_str[9];
    size_t ciph_key_size;
    size_t buff_s = BUFFLEAP;
    size_t input_len = 0;
    ssize_t read_len = -1;
    size_t output_len;
    
    int in = fileno(stdin);
    int out = fileno(stdout);
    ////GO////
    //read the email from stdin
    if (NULL == (email = malloc(BUFFLEAP))) exit(EXIT_FAILURE);
    while (read_len != 0)
    {
        read_len = read(in, email + input_len, buff_s - input_len);
        input_len += read_len;
        
        if (buff_s - input_len == 0) {      //on est au bout du buffer, il faut l'agrandir.
            buff_s = buff_s*4;
            if (buff_s > BUFFMAX_SIZE) exit(EXIT_FAILURE);
            if (NULL == (email = realloc(email, buff_s))) exit(EXIT_FAILURE);
        }
    }
    snprintf(input_len_str, 9,"%08zu", input_len);
    
    //get user infos
    if (argc != 2) goto do_not_cipher;
    user_id = strdup(argv[1]);
    //syslog (LOG_INFO|LOG_MAIL, "-> Encrypt arg : %s", user_id);
    pgsql_get_rsaPubKey(user_id, &rsa_pub_key, &do_crypt);
    if ((do_crypt == 'f') || (rsa_pub_key == NULL)) goto do_not_cipher;

    
    libgcrypt_initialize();
    
    // step 1 : generate a random 256bits key
    aes_plain_key = random_string2(32);
    if (aes_plain_key == NULL) goto do_not_cipher;
    
    //step 2 : cipher the email with that key
    if (aes_cipher(email, input_len, &cipher_email, aes_plain_key) == -1) goto do_not_cipher;
    
    //step 3 : cipher the aes key with the provided rsa public key
    ciph_key_size = rsa_cipher(aes_plain_key, &cipher_aes_key, rsa_pub_key);
    if (ciph_key_size == -1) goto do_not_cipher;
    snprintf(key_size_str, 4,"%03zu", ciph_key_size);
    
    //step 4 : concatenate mailden header + ciphered aes key + ciphered email
    //mailden header = ##mailden-00.00.00##xxxyyyyyyyy where xxx is ciphered_key_size and yyyyyyyy is email's initial length
    output_len = HEADER_SIZE + 3 + 8 + ciph_key_size + input_len;
    output = malloc(output_len);
    
    memcpy(output, header, HEADER_SIZE);
    memcpy(output + HEADER_SIZE, key_size_str, 3);
    memcpy(output + HEADER_SIZE + 3, input_len_str, 8);
    memcpy(output + HEADER_SIZE + 3 + 8, cipher_aes_key, ciph_key_size);
    memcpy(output + HEADER_SIZE + 3 + 8 + ciph_key_size, cipher_email, input_len);

    //output the ciphered email to stdout
    write(out, output, output_len);
    
    exit(EXIT_SUCCESS);
    
do_not_cipher:
    //concatenate mailden header + plain email
    ciph_key_size = 0;
    snprintf(key_size_str, 4,"%03zu", ciph_key_size);
    output_len = HEADER_SIZE + 3 + 8 + input_len;
    output = malloc(output_len);
    
    memcpy(output, header, HEADER_SIZE);
    memcpy(output + HEADER_SIZE, key_size_str, 3);
    memcpy(output + HEADER_SIZE + 3, input_len_str, 8);
    memcpy(output + HEADER_SIZE + 3 + 8, email, input_len);
    
    //output the plain email to stdout
    write(out, output, output_len);
    
    exit(EXIT_SUCCESS);

}

