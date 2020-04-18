#include "aes.h"

int encrypt(
    void* buffer,
    size_t buffer_len,
    char* IV, 
    char* key,
    size_t key_len 
){
	AES_KEY aes;
	unsigned char* input_string;
	size_t len;       
	//set the key
	if (AES_set_encrypt_key(key, 128, &aes) < 0) {
        fprintf(stderr, "Unable to set encryption key in AES\n");
        exit(-1);
    }
	//set the len
	len = 0;
    if ((buffer_len + 1) % AES_BLOCK_SIZE == 0) {
        len = buffer_len + 1;
    } else {
        len = ((buffer_len + 1) / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;
    }
    //set the input string
    input_string = (unsigned char*)calloc(len, sizeof(unsigned char));
    if (input_string == NULL) {
        fprintf(stderr, "Unable to allocate memory for input_string\n");
        exit(-1);
    }
    strncpy((char*)input_string, buffer, buffer_len);
    buffer = realloc(buffer, len);
    memset(buffer, 0, len); 
    // encrypt (iv will change)
    AES_cbc_encrypt(input_string, buffer, len, &aes, IV, AES_ENCRYPT);
    free(input_string);
	return len;
}

int decrypt(
    void* buffer,
    size_t buffer_len,
    char* IV, 
    char* key,
    size_t key_len 
){
	AES_KEY aes;
	unsigned char* input_string;
	if(buffer_len % AES_BLOCK_SIZE !=0)  return 0;
    //set the input string
    input_string = (unsigned char*)calloc(buffer_len, sizeof(unsigned char));
    if (input_string == NULL) {
        fprintf(stderr, "Unable to allocate memory for input_string\n");
        return 0;	
    }
    strncpy((char*)input_string, buffer, buffer_len);
    
    if (AES_set_decrypt_key(key, 128, &aes) < 0) {
        fprintf(stderr, "Unable to set decryption key in AES\n");
        return 0;
    }
    
	buffer = realloc(buffer, buffer_len);
	memset(buffer, 0, buffer_len);
	AES_cbc_encrypt(input_string, buffer, buffer_len, &aes, IV, AES_DECRYPT);
	
	free(input_string);
	return 1;
}


/*
int main()
{
//  MCRYPT td, td2;
  char * plaintext = "Test-teXt-123";
  char* IV = "AAAAAAAAAAAAAAAA";
  char *key = "0123456789abcdef";
  int keysize = 16; // 128 bits 
  char* buffer;
  int buffer_len = 16;

  buffer = calloc(1, buffer_len);
  strncpy(buffer, plaintext, buffer_len);

  printf("==C==\n");
  printf("plain:   %s\n", plaintext);
  encrypt(buffer, buffer_len, IV, key, keysize); 
  printf("cipher: %s\n ",buffer);// display(buffer , buffer_len);
  decrypt(buffer, buffer_len, IV, key, keysize);
  printf("decrypt: %s\n", buffer);
  
  return 0;
}*/
