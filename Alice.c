#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <strings.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#include "aes.h"
#include "ns.h"

#define ID				"Alice"
#define SECRET_KEY		"1000100010001000"
#define ADDRESS			"127.0.0.1"
#define PORT			20000

#define KDC_ID			"KDC"
#define KDC_ADDRESS		"127.0.0.1"
#define KDC_PORT		10000

#define TARGET_ID		"Bob"
#define TARGET_ADDRESS	"127.0.0.1"
#define TARGET_PORT		30000

int main()
{
	int cliSocket;
	struct sockaddr_in localAddr;
	struct sockaddr_in remoteAddrKDC, remoteAddrTarget;
	socklen_t addrlen = sizeof(struct sockaddr_in);
	
	//创建Alice端udp类型套接字
	cliSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	
	//初始化本地ipv4地址
	memset((char *) &localAddr, 0, sizeof(localAddr));
	localAddr.sin_family = AF_INET;
	localAddr.sin_port = htons(PORT);
	localAddr.sin_addr.s_addr = inet_addr(ADDRESS);
	
	//绑定套接字和本地ipv4地址
	bind(cliSocket, (const struct sockaddr *) &localAddr, sizeof(localAddr));

	//初始化kdc端ip地址（remoteAddrKDC）
	memset((char *) &remoteAddrKDC, 0, sizeof(remoteAddrKDC));
	remoteAddrKDC.sin_family = AF_INET;
	remoteAddrKDC.sin_port = htons(KDC_PORT);
	remoteAddrKDC.sin_addr.s_addr = inet_addr(KDC_ADDRESS);
	//初始化bob端ip地址（remoteAddrTarget）
	memset((char *) &remoteAddrTarget, 0, sizeof(remoteAddrTarget));
	remoteAddrTarget.sin_family = AF_INET;
	remoteAddrTarget.sin_port = htons(TARGET_PORT);
	remoteAddrTarget.sin_addr.s_addr = inet_addr(TARGET_ADDRESS);
	
	//buffer：数据暂存数组， IV：aes加密和解密所需初始向量
	char buffer[MAX_BUFFER_SIZE];
	//char IV[PLAINTEXT_KEY_SIZE];
	int len;
	
	//初始化IV向量
	//memset(IV, 'X', PLAINTEXT_KEY_SIZE);

	//Alice向KDC发送密钥请求
	struct kdc_request_s *request = (struct kdc_request_s *) malloc(sizeof(struct kdc_request_s));
	strcpy(request->senderHostname, ID);
	strcpy(request->receiverHostname, TARGET_ID);
	rand_nonce_gen(request->nonce1);
	printf("Sending Request to %s [%s, %s, %s]\n", KDC_ID, request->senderHostname, request->receiverHostname, request->nonce1);
	len = sendto(cliSocket, (void *) request, sizeof(struct kdc_request_s), 0, (const struct sockaddr*) &remoteAddrKDC, (socklen_t) addrlen);
	if(len == -1)
		goto main_END;
		
	//接收从KDC返回的响应
	struct kdc_reply_s *kdcReply = (struct kdc_reply_s *) malloc (sizeof(struct kdc_reply_s));
	len = recvfrom(cliSocket, (void *) kdcReply, sizeof(struct kdc_reply_s), 0, (struct sockaddr *) &remoteAddrKDC, (socklen_t *) &addrlen);
	if (len != sizeof(struct kdc_reply_s))
		goto main_END;
	decrypt((void *) kdcReply, sizeof(struct kdc_reply_s), /*IV, */SECRET_KEY, PLAINTEXT_KEY_SIZE);
	printf("Received Reply from %s [%s, %s, %s, <encrypted ticket>]\n", KDC_ID, kdcReply->sessionKey,kdcReply->receiverHostname,kdcReply->nonce1);

	//Alice发送加密信息给Bob
	printf("Sending <encrypted ticket> to %s\n", TARGET_ID);
	sendto(cliSocket, (void *) (kdcReply->encryptedTicket), sizeof(struct ticket_s), 0, (const struct sockaddr*) &remoteAddrTarget, (socklen_t) addrlen);
	if(len == -1)
		goto main_END;

	//Alice接收从Bob返回的challenge信息（用secertKey加密的Nonce2）
	memset((void *) buffer, 0, NONCE_LEN);
	len = recvfrom(cliSocket, (void *) buffer, NONCE_LEN, 0, (struct sockaddr *) &remoteAddrTarget, (socklen_t *) &addrlen);
	if (len != NONCE_LEN)
		goto main_END;
	buffer[len] = '\0';
	//printf("kdcReply->sessionKey is: %s\n", kdcReply->sessionKey);
	char *buffer2 = (char*)malloc(NONCE_LEN+1);
	strncpy(buffer2, buffer, len+1);
	decrypt((void *) buffer2, NONCE_LEN, /*IV, */kdcReply->sessionKey, strlen(kdcReply->sessionKey));
	strncpy(buffer, buffer2, len);
	buffer[len] = '\0';
	printf("Received Nonce2 from %s [%s]\n", TARGET_ID, buffer);
	
	// Alice给Bob发送确认信息(Nonce2 / 0x10 )
	buffer[NONCE_LEN-1] = '0';
	buffer[NONCE_LEN] = '\0';
	printf("Sending (Nonce2 / 0x10) to %s [%s]\n",  TARGET_ID, buffer);
	char *buffer3 = (char*)malloc(NONCE_LEN+1);
	strncpy(buffer3, buffer, NONCE_LEN+1);
	encrypt((void *) buffer3, NONCE_LEN, /*IV, */kdcReply->sessionKey, strlen(kdcReply->sessionKey));
	len = sendto(cliSocket, (void *) buffer3, NONCE_LEN, 0, (const struct sockaddr*) &remoteAddrTarget, (socklen_t) addrlen);
	if(len == -1)
		goto main_END;
	
main_END:
	close(cliSocket);
	return 0;
}
