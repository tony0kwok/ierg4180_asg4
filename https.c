#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
 
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

char *strtokm(char *str, const char *delim)
{
    static char *tok;
    static char *next;
    char *m;

    if (delim == NULL) return NULL;

    tok = (str) ? str : next;
    if (tok == NULL) return NULL;

    m = strstr(tok, delim);

    if (m) {
        next = m + strlen(delim);
        *m = '\0';
    } else {
        next = NULL;
    }

    return tok;
}

char *filename;
char *certhostname;
char *hostname;
char port[6];
char *resource;
int namesize;

char *http_proto;
char *http_resource;

char *response_header;
char *response_context;

long context_size;

long getContextSize(char *response_text){
    response_header = (char *)malloc(1024);
    response_context = (char *)malloc(1024);

    char *result;

    char *response = (char *)malloc(1024);
    strcpy(response, response_text);

    result = strstr(response, "Content-Length: ");

    if (result==NULL)
    {
        return 0;
    }

    result = strstr(result, " ");

    char *result2 = strstr(result, "\n");
    *result2 = '\0';

    long context_size = atol(result+1);

    //printf("size = %ld\n", context_size);
    
    return context_size;
}

void analysisURL(char *url_link){
    char url[100];
    strcpy(url, url_link);
    strcpy(http_proto, strtok(url, "://"));
    //printf("http_proto = %s\n", http_proto);
    strtok(NULL, ":");
    char *http_port = strtok(NULL, ":");
    //printf("port = %s\n", http_port);
    if (http_port!=NULL)
    {
        strcpy(port, http_port);
    }

    strcpy(url, url_link);

    strtok(url, "://");
    char *http_host = strtok(NULL, "//");
    //printf("http_host = %s\n", http_host);
    if (http_host!=NULL)
    {
        strcpy(hostname, http_host);
        strcpy(certhostname, http_host);
    }

    char *res = strtok(NULL, ":");
    if (res != NULL)
    {
        strcat(http_resource, res);
    }
    
    //printf("http_resource = %s\n", http_resource);
}

int setting(int argc, char** argv){
    namesize = 1000;
    certhostname = (char *)malloc(namesize);
    hostname = (char *)malloc(namesize);
    filename = NULL;
    http_resource = (char *)malloc(namesize);
    http_proto = (char *)malloc(namesize);

    strcpy(http_resource, "/");

    //default setting
    strcpy(hostname, "localhost");
    strcpy(port, "443");

    analysisURL(argv[1]); 
    //printf("http_host = %s\n", hostname);
    //printf("http_proto = %s\n", http_proto);
    //printf("http_resource = %s\n", http_resource);
    //printf("port = %s\n", port);

    const char *optstring = "f:h:";
    int c;
    struct option opts[] = {
        {"file", 1, NULL, 'f'},
        {"verifyhost", 1, NULL, 'h'}
    };
    while((c = getopt_long_only(argc, argv, optstring, opts, NULL)) != -1) {
        switch(c) {
            case 'f':
                filename = (char *)malloc(namesize);
                strcpy(filename, optarg);
                break;
            case 'h':
                strcpy(certhostname, optarg);
                break;
            case '?':
                printf("unknown option\n");
                break;
            case 0 :
                printf("the return val is 0\n");
                break;
            default:
                printf("------\n");
        }
    }
}
 
// Simple structure to keep track of the handle, and
// of what needs to be freed later.
typedef struct
{
    int socket;
    SSL *sslHandle;
    SSL_CTX *sslContext;
} connection;
 
#define PORT 80
 
// Establish a regular tcp connection
int tcpConnect ()
{
    int error, handle;
    struct hostent *host;
    struct sockaddr_in server;
 
    host = gethostbyname (hostname);
    handle = socket (AF_INET, SOCK_STREAM, 0);
    if (handle == -1)
    {
        perror ("Socket");
        handle = 0;
    }
    else
    {
        server.sin_family = AF_INET;
        server.sin_port = htons (PORT);
        server.sin_addr = *((struct in_addr *) host->h_addr);
        bzero (&(server.sin_zero), 8);
 
        error = connect (handle, (struct sockaddr *) &server,
                         sizeof (struct sockaddr));
        if (error == -1)
        {
            perror ("Connect");
            handle = 0;
        }
    }
 
    return handle;
}
 
// Establish a connection using an SSL layer
connection *sslConnect (void)
{
    connection *c;
 
    c = malloc (sizeof (connection));
    c->sslHandle = NULL;
    c->sslContext = NULL;
 
    c->socket = tcpConnect ();
    if (c->socket)
    {
        if (strcmp(http_proto, "https")==0)
        {
        
            // Register the error strings for libcrypto & libssl
            SSL_load_error_strings ();

            // Register the available ciphers and digests
            SSL_library_init ();
            OpenSSL_add_all_algorithms();
     
            // New context saying we are a client, and using SSL 2 or 3
            c->sslContext = SSL_CTX_new (SSLv23_client_method ());
            if (c->sslContext == NULL)
                ERR_print_errors_fp (stderr);
     
            // Create an SSL struct for the connection
            c->sslHandle = SSL_new (c->sslContext);
            if (c->sslHandle == NULL)
                ERR_print_errors_fp (stderr);
     
            // Connect the SSL struct to our connection
            if (!SSL_set_fd (c->sslHandle, c->socket))
                ERR_print_errors_fp (stderr);
     
            // Initiate SSL handshake
            if (SSL_connect (c->sslHandle) != 1)
                ERR_print_errors_fp (stderr);
        }
    }
    else
    {
        perror ("Connect failed");
    }
 
    return c;
}
 
// Disconnect & free connection struct
void sslDisconnect (connection *c)
{
    if (c->socket)
        close (c->socket);
    if (c->sslHandle)
    {
        SSL_shutdown (c->sslHandle);
        SSL_free (c->sslHandle);
    }
    if (c->sslContext)
        SSL_CTX_free (c->sslContext);
 
    free (c);
}
 
// Read all available text from the connection
char *sslRead (connection *c)
{
    long onetime_readSize = 1024, readSize = 100000;
    char *rc = NULL;
    long received = 0, onetime_received = 0;
    char *buffer;
 
    if (c)
    {
        rc = malloc (readSize * sizeof (char) + 1 + 1000);
        memset(rc,'\0',readSize + 1);
        buffer = malloc (onetime_readSize * sizeof (char) + 1);
        int skip = 0;
        int loop = 0;
        while (1)
        {
            memset(buffer,'\0',onetime_readSize + 1);
            if(strcmp(http_proto, "https")==0)
            {
                onetime_received = SSL_read (c->sslHandle, buffer, onetime_readSize);
                
            }
            else
            if (strcmp(http_proto, "http")==0)
            {
                onetime_received = recv(c->socket, buffer, onetime_readSize, 0);
                
            }
            //printf("buffer = %s\n", buffer);
            if (loop==0)
            {
                if((context_size = getContextSize(buffer))>0)
                {
                    printf("here1\n");
                    free(rc);
                    rc = malloc (context_size * sizeof (char) + 1 + 1000);
                    memset(rc,'\0',context_size + 1);
                    readSize = context_size;
                }
                else
                {
                    context_size = readSize;
                }
                char *temp = strstr(buffer, "\r\n\r\n");
                //printf("buffer = %s\n", buffer);
                //printf("temp = %s\n", temp);
                if (temp!=NULL)
                {
                    strcpy(buffer, temp);
                }
                else
                {
                    strcpy(buffer, "");
                }
            }
            if (onetime_received<=-1)
            {
                perror("error: ");
                break;
            }
            else
            {
                received += onetime_received;
                if (buffer!=NULL)
                {
                    buffer[onetime_received] = '\0';
                    strcat (rc, buffer);
                }
                
            }
            if (onetime_received==0)
            {
                printf("received 0 bytes\n");
                break;
            }
            if (received>=readSize)
            {
                break;
            }
            loop+=1;
            //printf("received = %ld\n", received);
            
 
            /*if (onetime_received > 0)
                strcat (rc, buffer);
 
            if (received < readSize)
                break;
            count++;*/
        }
    }

    rc[readSize+1] = '\0';
    printf("received = %ld\n", received);
    printf("readSize = %ld\n", readSize);
    //printf("rc = %s\n", rc);
    return rc;
}
 
// Write text to the connection
void sslWrite (connection *c, char *text)
{
    if (c)
    {
        if (strcmp(http_proto, "https")==0)
        {
            SSL_write (c->sslHandle, text, strlen (text));
        }
        else
        {
            send(c->socket, text, strlen (text), 0);
        }
        
    }
}
 
// Very basic main: we send GET / and print the response.
int main (int argc, char **argv)
{
    connection *c;
    char *response;

    /*//get ipv6 address
    int gaiStatus; // getaddrinfo 狀態碼
    struct addrinfo hints; // hints 參數，設定 getaddrinfo() 的回傳方式
    struct addrinfo *result, *udp_result; // getaddrinfo() 執行結果的 addrinfo 結構指標

    // 以 memset 清空 hints 結構
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = inet_type; // 使用 IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM; // 串流 Socket
    hints.ai_flags = AI_NUMERICSERV; // 將 getaddrinfo() 第 2 參數 (PORT_NUM) 視為數字

    // 以 getaddrinfo 透過 DNS，取得 addrinfo 鏈結串列 (Linked List)
    // 以從中取得 Host 的 IP 位址
    if ((gaiStatus = getaddrinfo(strcmp(hostname, "localhost")==0?NULL:hostname, port_num, &hints, &result)) != 0)
        errExit((char *) gai_strerror(gaiStatus));*/
    setting(argc, argv);
    c = sslConnect();
    
    char *ssl_message = (char *)malloc(10000);
    strcpy(ssl_message, "GET ");
    strcat(ssl_message, http_resource);
    strcat(ssl_message, " HTTP/1.1\r\nHost: ");
    strcat(ssl_message, certhostname);
    strcat(ssl_message, "\r\nKeep-Alive: 10\r\nConnection: keep-alive\r\n\r\n");
    printf("request:\n%s\n", ssl_message);
    sslWrite (c, ssl_message);
    printf("start read\n");
    response = sslRead(c);
    printf("end read\n");
       
    if (filename==NULL)
    {
        printf("%s\n", response);
    }
    else
    {
        FILE *fp = fopen(filename, "w");
        fwrite(response, 1, context_size, fp);
    }
    //printf ("%s\n", response);
 
    sslDisconnect(c);
    free(response);
 
    return 0;
}