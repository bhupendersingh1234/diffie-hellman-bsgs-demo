/*
 * Diffie-Hellman Client
 * Compile: gcc -o dh_client dh_client.c
 * Run:     ./dh_client
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#ifdef _WIN32
  #include <winsock2.h>
  #pragma comment(lib,"ws2_32.lib")
  typedef SOCKET sock_t;
#else
  #include <unistd.h>
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  typedef int sock_t;
  #define INVALID_SOCKET -1
  #define SOCKET_ERROR   -1
  #define closesocket close
#endif

#define PORT 9090
#define HOST "127.0.0.1"

typedef unsigned long long u64;

static u64 mulmod(u64 a, u64 b, u64 m) {
    u64 result = 0; a %= m;
    while (b > 0) {
        if (b & 1) result = (result + a) % m;
        a = (a * 2) % m; b >>= 1;
    }
    return result;
}

static u64 powmod(u64 base, u64 exp, u64 mod) {
    u64 result = 1; base %= mod;
    while (exp > 0) {
        if (exp & 1) result = mulmod(result, base, mod);
        base = mulmod(base, base, mod); exp >>= 1;
    }
    return result;
}

int main(void) {
#ifdef _WIN32
    WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);
#endif
    srand((unsigned)time(NULL));

    sock_t s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) { perror("socket"); return 1; }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(PORT);
    addr.sin_addr.s_addr = inet_addr(HOST);

    if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        perror("connect"); closesocket(s); return 1;
    }
    printf("Connected to server.\n");

    /* Receive parameters — these appear in plaintext in Wireshark */
    char buf[256] = {0};
    recv(s, buf, sizeof(buf)-1, 0);
    printf("Server says: %s", buf);

    u64 g, p, A;
    sscanf(buf, "DH g=%llu p=%llu A=%llu", &g, &p, &A);
    printf("Parsed: g=%llu  p=%llu  A(server pubkey)=%llu\n",
           (unsigned long long)g, (unsigned long long)p, (unsigned long long)A);

    /* Client private key b (random small) */
    u64 b = (u64)(rand() % ((int)p - 2)) + 1;
    u64 B = powmod(g, b, p);
    printf("Client private key b = %llu\n", (unsigned long long)b);
    printf("Client public  key B = %llu  [g^b mod p]\n", (unsigned long long)B);

    char reply[64];
    snprintf(reply, sizeof(reply), "B=%llu\n", (unsigned long long)B);
    send(s, reply, (int)strlen(reply), 0);

    u64 shared = powmod(A, b, p);
    printf("Shared secret = %llu\n", (unsigned long long)shared);

    closesocket(s);
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
