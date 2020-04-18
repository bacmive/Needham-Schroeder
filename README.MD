# NS协议

##ns.h介绍

###宏
MAX_BUFFER_SIZE 缓冲区最大长度
MAX_HOSTS 通信主体最大个数（在KDC.c中使用）
PLAINTEXT_KEY_SIZE 字符串型密钥长度
HOSTNAME_SIZE 通信主体名字长度
NONCE_LEN 随机数长度（字符串类型）

###结构体
struct host_s:  通信主体身份标识，包含：
				hostname (字符串)
				secretKey (字符串)

struct session_s: 在KDC中使用，某两个主体（clients)需要通信时，由kdc创建关于这两个clients的信息
				  host1 (struct host_s *)
				  host2 (struct host_s *)
				  sessionKey （字符串） //Alice和Bob的通信密钥

struct kdc_request_s： Alice发起密钥请求时，给KDC发送的请求报文（协议的第一步骤），包含：
					  senderHostname （字符串） //发送方名字，例： “Alice"
					  receiverHostname (字符串） //接收方名字， 例：“Bob”
					  nonce1 （字符串） //随机数，转换成的16进制数的字符表示

struct kdc_reply_s： KDC响应Alice时，发送给Alice的响应报文，包含：
					nonce1 （字符串） 随机数
					receiverHostname (字符串）
					sessionKey （字符串）
					encryptedTicket （包含sessionKey和senderHostname）

struct ticket_s： Alice发送给Bob的通信请求（协议的第三步周），包含：
				 senderHostname（字符串） 
				 sessionKey （字符串）
				 

###函数

void allocateRandomString(char *str, size_t size);
产生随机密钥， str为传出参数

struct session_s* createSession(struct host_s *host1, struct host_s *host2)
由KDC调用，创建通信信息

void rand_nonce_gen(char *nonce)
随机数生成， nonce为传入/传出参数
				

##aes.h介绍

###宏
AES_BLOCK_SIZE 加密算法aes的加密块长度

###函数
int encrypt(void* buffer, size_t buffer_len, char* key, size_t key_len);
加密函数，buffer为传入/传出参数，传入的是待加密数据，传出的是加密后的数据
		key为加密密钥

int decrypt(void* buffer, size_t buffer_len, char* key, size_t key_len);
解密函数，buffer为传入/传出参数，传入的是已加密数据，传出的是解密后的数据
		key为解密密钥


##执行过程
0.在本目录下运行make

1.先运行kdc程序，即先给A、B两个需要互相通信的节点分发各自的密钥ka，kb
（在此程序中，分发密钥的过程被模拟为给对应的文件A.txt、B.txt中写入各自密钥）

2.此程序模拟的是A主动发起和B的通信，于是再运行B程序，让B处于等待通信的状态；

3.最后运行A程序，A主动与B通信过程：
	3.1 A向KDC发送与B通信的请求，具体为： A->KDC: IDA,IDB,N1;
	3.2 KDC响应A，返回一个AB间通信密钥ks，具体为： KDC->A： Eka(ks, IDB, N1, Ekb(ks, IDA))
	3.3 A向B发送连接请求，附带AB间通信密钥ks，具体为：A->B: Ekb(ks,IDA);
	3.4 B响应A一个用ks加密的Nonce, 具体为：B->A: Eks(N2);
	3.5 A向B再回复确实得到了ks，具体为: A->B: Eks(f(N2));

4. 最后A、B双方都确认得到通信密钥ks


