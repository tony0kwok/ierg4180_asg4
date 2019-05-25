all: https

https: https.c
	gcc -o client https.c -lssl -lcrypto