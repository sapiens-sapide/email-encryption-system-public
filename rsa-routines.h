//
//  rsa-routines.h
//  encrypt_One
//
//  Created by Stanislas SABATIER on 26/05/2014.
//  Copyright (c) 2014 Stanislas SABATIER. All rights reserved.
//

#ifndef encrypt_One_rsa_routines_h
#define encrypt_One_rsa_routines_h
#include <stdio.h>
#include <gcrypt.h>
#include "Tools.h"

void generate_rsa_keypair (char **rsapub, char **rsapriv);

#endif
