#ifndef _AES_H_
#define _AES_H_

#define AES_BLOCK_SIZE 16
int encrypt(void* buffer, size_t buffer_len, char* key, size_t key_len);
int decrypt(void* buffer, size_t buffer_len, char* key, size_t key_len);


#endif
