#include <stdio.h>
#include "aes.h"

int main()
{
	char *test = "12121212121212121212121212121212";
	char *buffer =(char *)malloc(32);
	char IV[16];
	memset(IV, 'X', 16);
	char *key = "12121212121212121212121212121212";
	memset((void*)buffer, 0, 32);
	memcpy((void *) buffer, test, 32);
	puts(buffer);
	encrypt(buffer, 32, IV, key, strlen(key));
	puts(buffer);
	//free(buffer);
	
	return 0;
}
