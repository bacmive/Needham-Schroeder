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

#define ID			"Bob"
#define SECRET_KEY	"1200120012001200"
#define ADDRESS		"127.0.0.1"
#define PORT		30000

int main()
{
	int cliSocket;
	struct sockaddr_in localAddr;
	struct sockaddr_in remoteAddrSource;
	socklen_t addrlen = sizeof(struct sockaddr_in);

	cliSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	
	memset((char *) &localAddr, 0, sizeof(localAddr));
	localAddr.sin_family = AF_INET;
	localAddr.sin_port = htons(PORT);
	localAddr.sin_addr.s_addr = inet_addr(ADDRESS);

	bind(cliSocket, (const struct sockaddr *) &localAddr, sizeof(localAddr));

	char buffer[MAX_BUFFER_SIZE];
	char buffer_1[MAX_BUFFER_SIZE];
	//char IV[PLAINTEXT_KEY_SIZE];
	int len;

	//memset(IV, 'X', PLAINTEXT_KEY_SIZE);

	// 从Alice接收密钥会话信息
	struct ticket_s *ticket = (struct ticket_s *) malloc(sizeof(struct ticket_s));
	len = recvfrom(cliSocket, (void *) ticket, sizeof(struct ticket_s), 0, (struct sockaddr *) &remoteAddrSource, (socklen_t *) &addrlen);
	if (len != sizeof(struct ticket_s))
		goto main_END;	
	decrypt((void *) ticket, sizeof(struct ticket_s), /*IV, */ SECRET_KEY, PLAINTEXT_KEY_SIZE);
	printf("Received <encrypted ticket> from %s [%s, %s]\n", ticket->senderHostname, ticket->senderHostname, ticket->sessionKey);

	// 发送challenge信息给Alice（Nonce2）
	rand_nonce_gen(buffer);
	buffer[NONCE_LEN] = '\0';
	strncpy(buffer_1, buffer, NONCE_LEN+1);
	printf("Sending Nonce2 to %s [%s]\n", ticket->senderHostname, buffer);
	//printf("ticket->sessionkey is: %s\n", ticket->sessionKey);
	char *buffer2 = (char*)malloc(NONCE_LEN+1);
	strncpy(buffer2, buffer, NONCE_LEN+1);
	encrypt((void *) buffer2, NONCE_LEN, /*IV, */ticket->sessionKey, PLAINTEXT_KEY_SIZE);
	len = sendto(cliSocket, (void *) buffer2, NONCE_LEN, 0, (const struct sockaddr*) &remoteAddrSource, (socklen_t) addrlen);
	if(len == -1)
		goto main_END;
		
	// 从Alice接收确认信息（Nonce2 / 0x10)
	memset((void *) buffer, 0, NONCE_LEN);
	len = recvfrom(cliSocket, (void *) buffer, NONCE_LEN, 0, (struct sockaddr *) &remoteAddrSource, (socklen_t *) &addrlen);
	if (len != NONCE_LEN)
		goto main_END;
	buffer[len] = '\0';
	char *buffer3 = (char*)malloc(NONCE_LEN);
	memcpy(buffer3, buffer, len+1);
	decrypt((void *) buffer3, NONCE_LEN, /*IV, */ticket->sessionKey, PLAINTEXT_KEY_SIZE);
	printf("Received (Nonce2 / 0x10) from %s [%s]\n", ticket->senderHostname, buffer3);
	buffer_1[NONCE_LEN-1] = '0';
	if(memcmp(buffer3, buffer_1, NONCE_LEN) !=0)
		printf("FAIL!\n");
	else
		printf("SUCCESS\n");
	
main_END:
	close(cliSocket);
	return 0;
}
