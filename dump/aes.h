#ifndef AES_H
#define AES_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <openssl/aes.h>

#define AES_BLOCK_SIZE 16

int encrypt(
    void* buffer,
    size_t buffer_len,
    char* IV, 
    char* key,
    size_t key_len 
);

int decrypt(
    void* buffer,
    size_t buffer_len,
    char* IV, 
    char* key,
    size_t key_len 
);



#endif //	AES_H
