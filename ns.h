#ifndef _NS_H_
#define _NS_H_

#include <openssl/bn.h> 

#define MAX_BUFFER_SIZE		720
#define MAX_HOSTS			3
#define PLAINTEXT_KEY_SIZE	16
#define HOSTNAME_SIZE		32
#define NONCE_LEN           32

struct host_s
{
	char hostname[HOSTNAME_SIZE * 2];//64
	char secretKey[PLAINTEXT_KEY_SIZE * 2];//32
};

struct session_s
{
	struct host_s *host1;//8
	struct host_s *host2;//8
	char sessionKey[PLAINTEXT_KEY_SIZE * 2];//32
};

struct kdc_request_s
{
	char senderHostname[HOSTNAME_SIZE * 2];//64
	char receiverHostname[HOSTNAME_SIZE * 2];//64
	char nonce1[NONCE_LEN];//32
};

struct ticket_s
{
	char senderHostname[HOSTNAME_SIZE * 2];//64
	char sessionKey[PLAINTEXT_KEY_SIZE * 2];//32
};

struct kdc_reply_s
{
	char nonce1[NONCE_LEN*2];//64
	char receiverHostname[HOSTNAME_SIZE * 2];//64
	char sessionKey[PLAINTEXT_KEY_SIZE * 2];//32
	char encryptedTicket[sizeof(struct ticket_s)];//96
};



void allocateRandomString(char *str, size_t size)
{
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789,.-#'?!";
    if (size)
    {
        for (size_t n = 0; n < size; ++n)
        {
            int key = rand() % (int) (sizeof(charset) - 1);
            str[n] = charset[key];
        }
        str[size] = '\0';
    }
}

struct session_s* createSession(struct host_s *host1, struct host_s *host2)
{
	struct session_s *ret = (struct session_s *) malloc (sizeof(struct session_s));
	ret->host1 = host1;
	ret->host2 = host2;
	allocateRandomString(ret->sessionKey, PLAINTEXT_KEY_SIZE);
	return ret;
}

void rand_nonce_gen(char *nonce)
{
	BIGNUM *bn = BN_new();
	int bits = NONCE_LEN*4;//生成随机数位数
    int top = 1;//随机首位可以为0
    int bottom = 0;//bottom为1则得到的数为奇数
	BN_rand(bn, bits, top, bottom);//生成的随机数保存在BN结构中
	char *a = BN_bn2hex(bn); //转化成16进制字符串 
	strncpy(nonce, a, NONCE_LEN);
	BN_free(bn);
}
#endif //	_NS_H_
