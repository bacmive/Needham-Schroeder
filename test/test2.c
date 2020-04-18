#include <stdio.h>
#include "aes.h"
#include <string.h>
#include <stdlib.h>


int main()
{
	char * plaintext = "Test-teXt-123456";
	char *key = "1234567890asdfgh";
	int keysize = 16; // 128 bits 
	char* buffer;
	int buffer_len = 16;

	buffer = calloc(buffer_len, sizeof(char));
	strncpy(buffer, plaintext, buffer_len);

	printf("plain:   %s\n", plaintext);
	encrypt(buffer, buffer_len, key, keysize); 
	printf("cipher: %s\n ",buffer);// display(buffer , buffer_len);
	
	char *key2 = "1111111111111111";
	decrypt(buffer, buffer_len, key2, keysize);
	printf("decrypt: %s, len is %zu\n", buffer, strlen(buffer));
	
	
	return 0;

}
