/*
 * Diffie-Hellman Server
 * Compile: gcc -o dh_server dh_server.c
 * Run:     ./dh_server
 * Sniff with Wireshark on loopback (lo) port 9090 to capture g, p, n (public key)
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

/* ---------- tiny bignum helpers (64-bit only, small params) ---------- */

typedef unsigned long long u64;

/* Miller-Rabin primality test (deterministic for n < 3.3e24 with these witnesses) */
static u64 mulmod(u64 a, u64 b, u64 m) {
    u64 result = 0;
    a %= m;
    while (b > 0) {
        if (b & 1) result = (result + a) % m;
        a = (a * 2) % m;
        b >>= 1;
    }
    return result;
}

static u64 powmod(u64 base, u64 exp, u64 mod) {
    u64 result = 1;
    base %= mod;
    while (exp > 0) {
        if (exp & 1) result = mulmod(result, base, mod);
        base = mulmod(base, base, mod);
        exp >>= 1;
    }
    return result;
}

static int miller_rabin_witness(u64 n, u64 a) {
    if (n % a == 0) return n == a;
    u64 d = n - 1;
    int r = 0;
    while (d % 2 == 0) { d /= 2; r++; }
    u64 x = powmod(a, d, n);
    if (x == 1 || x == n - 1) return 1;
    for (int i = 0; i < r - 1; i++) {
        x = mulmod(x, x, n);
        if (x == n - 1) return 1;
    }
    return 0;
}

int is_prime(u64 n) {
    if (n < 2) return 0;
    if (n == 2 || n == 3 || n == 5 || n == 7) return 1;
    if (n % 2 == 0 || n % 3 == 0) return 0;
    /* deterministic witnesses for n < 3,317,044,064,679,887,385,961,981 */
    u64 witnesses[] = {2,3,5,7,11,13,17,19,23,29,31,37};
    for (int i = 0; i < 12; i++)
        if (!miller_rabin_witness(n, witnesses[i])) return 0;
    return 1;
}

/* Small safe prime p=23, g=5 (toy example visible in Wireshark) */
#define DEMO_P 23ULL
#define DEMO_G 5ULL

int main(void) {
#ifdef _WIN32
    WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);
#endif
    srand((unsigned)time(NULL));

    u64 p = DEMO_P, g = DEMO_G;
    /* server private key a, public key A = g^a mod p */
    u64 a = 6ULL; /* private */
    u64 A = powmod(g, a, p); /* public */

    printf("=== DH Server ===\n");
    printf("Parameters sent in PLAINTEXT (capture with Wireshark on port %d):\n", PORT);
    printf("  p (prime)        = %llu\n", (unsigned long long)p);
    printf("  g (generator)    = %llu\n", (unsigned long long)g);
    printf("  A (public key/n) = %llu  [g^a mod p, a=%llu]\n",
           (unsigned long long)A, (unsigned long long)a);

    sock_t srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv == INVALID_SOCKET) { perror("socket"); return 1; }

    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(PORT);

    if (bind(srv, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        perror("bind"); closesocket(srv); return 1;
    }
    listen(srv, 1);
    printf("Listening on port %d … (connect with dh_client)\n", PORT);

    sock_t cli = accept(srv, NULL, NULL);
    if (cli == INVALID_SOCKET) { perror("accept"); closesocket(srv); return 1; }
    printf("Client connected.\n");

    /* Send g, p, A as plain ASCII — Wireshark will show these */
    char msg[256];
    snprintf(msg, sizeof(msg), "DH g=%llu p=%llu A=%llu\n",
             (unsigned long long)g,
             (unsigned long long)p,
             (unsigned long long)A);
    send(cli, msg, (int)strlen(msg), 0);

    /* Receive client public key B */
    char buf[256] = {0};
    recv(cli, buf, sizeof(buf)-1, 0);
    u64 B = 0;
    sscanf(buf, "B=%llu", &B);
    printf("Received client public key B = %llu\n", (unsigned long long)B);

    u64 shared = powmod(B, a, p);
    printf("Shared secret = %llu\n", (unsigned long long)shared);

    closesocket(cli);
    closesocket(srv);
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
