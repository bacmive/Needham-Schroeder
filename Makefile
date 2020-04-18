all:
	gcc -o kdc KDC.c aes.c -lcrypto
	gcc -o A Alice.c aes.c -lcrypto
	gcc -o B   Bob.c aes.c -lcrypto

clean:
	rm -f A B kdc
