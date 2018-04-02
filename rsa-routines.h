//
//  rsa-routines.h
//  encrypt_One
//
// Copyleft (ɔ) 2014 Mailden
// Use of this source code is governed by a GNU AFFERO GENERAL PUBLIC
// license (AGPL) that can be found in the LICENSE file.

#ifndef encrypt_One_rsa_routines_h
#define encrypt_One_rsa_routines_h
#include <stdio.h>
#include <gcrypt.h>
#include "Tools.h"

void generate_rsa_keypair (char **rsapub, char **rsapriv);

#endif
