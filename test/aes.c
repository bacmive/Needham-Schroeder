#include <stdio.h>
#include <string.h>	
#include <stdlib.h>
#include <unistd.h>
#include <openssl/aes.h>

#include "aes.h"

int encrypt(void* buffer, size_t buffer_len, char* key, size_t key_len)
{
	AES_KEY aeskey;
	AES_set_encrypt_key(key, AES_BLOCK_SIZE*8, &aeskey);
	
	unsigned char *data = (unsigned char *)buffer;
	unsigned char *encrypt =(unsigned char *) malloc(buffer_len);
	
	int i = 0 , len = buffer_len/AES_BLOCK_SIZE;
    /*循环加密，每次只能加密AES_BLOCK_SIZE长度的数据*/
    while(i < buffer_len) {
        AES_encrypt(data+i, encrypt+i, &aeskey);    
        i += AES_BLOCK_SIZE;
    }	
	memcpy(buffer, encrypt, buffer_len);
	free(encrypt);
	return 1;
}

int decrypt(void* buffer, size_t buffer_len, char* key, size_t key_len)
{
	AES_KEY aeskey;
	AES_set_decrypt_key(key, AES_BLOCK_SIZE*8, &aeskey);
	
	unsigned char *data = (unsigned char *)buffer;
	unsigned char *decrypt =(unsigned char *) malloc(buffer_len);
	
	
	int i=0, len = buffer_len/AES_BLOCK_SIZE;
    /*循环解密*/
    while(i < buffer_len) {
        AES_decrypt(data+i, decrypt+i, &aeskey);    
		i += AES_BLOCK_SIZE;
    }
    memcpy(buffer, decrypt, buffer_len);
    free(decrypt);
    return 1;
}



//int main(void)
//{
    //char userkey[AES_BLOCK_SIZE];
    //unsigned char *data = malloc(AES_BLOCK_SIZE*3);
    //unsigned char *encrypt = malloc(AES_BLOCK_SIZE*3 + 4);
    //unsigned char *plain = malloc(AES_BLOCK_SIZE*3);
    //AES_KEY key;
 
    //memset((void*)userkey, 'k', AES_BLOCK_SIZE);
    //memset((void*)data, 'p', AES_BLOCK_SIZE*3);
    //memset((void*)encrypt, 0, AES_BLOCK_SIZE*6);
    //memset((void*)plain, 0, AES_BLOCK_SIZE*3);
 
    ///*设置加密key及密钥长度*/
    //AES_set_encrypt_key(userkey, AES_BLOCK_SIZE*8, &key);
 
    //int len = 0;
    ///*循环加密，每次只能加密AES_BLOCK_SIZE长度的数据*/
    //while(len < AES_BLOCK_SIZE*3) {
        //AES_encrypt(data+len, encrypt+len, &key);    
        //len += AES_BLOCK_SIZE;
    //}
    ///*设置解密key及密钥长度*/    
    //AES_set_decrypt_key(userkey, AES_BLOCK_SIZE*8, &key);
 
    //len = 0;
    ///*循环解密*/
    //while(len < AES_BLOCK_SIZE*3) {
        //AES_decrypt(encrypt+len, plain+len, &key);    
        //len += AES_BLOCK_SIZE;
    //}
    
    ///*解密后与原数据是否一致*/
    //if(!memcmp(plain, data, AES_BLOCK_SIZE*3)){
        //printf("test success\n");    
    //}else{
        //printf("test failed\n");    
    //}
	
    //printf("encrypt: ");
    //int i = 0;
    //for(i = 0; i < AES_BLOCK_SIZE*3 + 4; i++){
        //printf("%.2x ", encrypt[i]);
        //if((i+1) % 32 == 0){
            //printf("\n");    
        //}
    //}
    //printf("\n");    
	
	//printf("------for test-------\n");
	//printf("encrypt: ");
	//encrypt_f(plain, AES_BLOCK_SIZE*3, userkey, AES_BLOCK_SIZE);
	//for(i = 0; i < AES_BLOCK_SIZE*3; i++){
        //printf("%.2x ", plain[i]);
        //if((i+1) % 32 == 0){
            //printf("\n");    
        //}
    //}
    //printf("\n");
    
    //printf("------for comp--------\n");
    //decrypt_f(plain, AES_BLOCK_SIZE*3, userkey, AES_BLOCK_SIZE);
    //if(!memcmp(plain, data, AES_BLOCK_SIZE*3)){
        //printf("test success\n");    
    //}else{
        //printf("test failed\n");    
    //}
 
    //return 0;
//}

