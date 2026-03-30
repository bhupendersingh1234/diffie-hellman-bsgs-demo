/*
 * Baby-Step Giant-Step (BSGS) Discrete Logarithm Attacker
 * Solves: g^x ≡ n (mod p)  for x (the private key)
 *
 * Compile: gcc -O2 -o bsgs_attack bsgs_attack.c
 * Usage:   ./bsgs_attack <g> <p> <n>
 *   or     ./bsgs_attack          (interactive, enter g p n)
 *
 * Feed the values you captured from Wireshark!
 * Works for group order up to ~2^20 comfortably (RAM: O(sqrt(p))).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <stdint.h>

typedef unsigned long long u64;

/* ---- modular arithmetic ---- */
static u64 mulmod(u64 a, u64 b, u64 m) {
    /* __uint128_t for no-overflow on 64-bit platforms */
#if defined(__GNUC__) && defined(__x86_64__)
    return (u64)((__uint128_t)a * b % m);
#else
    u64 r = 0; a %= m;
    while (b) { if (b & 1) r = (r + a) % m; a = (a + a) % m; b >>= 1; }
    return r;
#endif
}

static u64 powmod(u64 b, u64 e, u64 m) {
    u64 r = 1; b %= m;
    while (e) { if (e & 1) r = mulmod(r, b, m); b = mulmod(b, b, m); e >>= 1; }
    return r;
}

/* ---- modular inverse via extended Euclidean ---- */
static long long ext_gcd(long long a, long long b, long long *x, long long *y) {
    if (b == 0) { *x = 1; *y = 0; return a; }
    long long x1, y1;
    long long g = ext_gcd(b, a % b, &x1, &y1);
    *x = y1; *y = x1 - (a / b) * y1;
    return g;
}

static u64 modinv(u64 a, u64 m) {
    long long x, y;
    long long g = ext_gcd((long long)a, (long long)m, &x, &y);
    if (g != 1) return (u64)-1; /* no inverse */
    return (u64)((x % (long long)m + (long long)m) % (long long)m);
}

/* ---- simple hash table for baby steps ---- */
#define HASH_SIZE (1 << 22)  /* 4M buckets */
#define HASH_MASK (HASH_SIZE - 1)

typedef struct Entry { u64 val; u64 exp; struct Entry *next; } Entry;
static Entry *table[HASH_SIZE];
static Entry *pool = NULL;
static size_t pool_idx = 0;
static size_t pool_cap = 0;

static void ht_init(size_t cap) {
    memset(table, 0, sizeof(table));
    pool_cap = cap + 16;
    pool = (Entry*)malloc(pool_cap * sizeof(Entry));
    pool_idx = 0;
}

static void ht_free(void) { free(pool); pool = NULL; }

static void ht_insert(u64 val, u64 exp) {
    u64 h = (val ^ (val >> 17) ^ (val >> 31)) & HASH_MASK;
    Entry *e = &pool[pool_idx++];
    e->val = val; e->exp = exp; e->next = table[h];
    table[h] = e;
}

static u64 ht_lookup(u64 val) {
    u64 h = (val ^ (val >> 17) ^ (val >> 31)) & HASH_MASK;
    for (Entry *e = table[h]; e; e = e->next)
        if (e->val == val) return e->exp;
    return (u64)-1;
}

/* ---- Miller-Rabin primality (same as server) ---- */
static int miller_witness(u64 n, u64 a) {
    if (n % a == 0) return n == a;
    u64 d = n-1; int r = 0;
    while (d%2==0){d/=2;r++;}
    u64 x = powmod(a,d,n);
    if(x==1||x==n-1) return 1;
    for(int i=0;i<r-1;i++){x=mulmod(x,x,n);if(x==n-1)return 1;}
    return 0;
}
static int is_prime(u64 n) {
    if(n<2) return 0;
    u64 ws[]={2,3,5,7,11,13,17,19,23,29,31,37};
    for(int i=0;i<12;i++) if(!miller_witness(n,ws[i])) return 0;
    return 1;
}

/* ---- BSGS ---- */
/*
 * Solve g^x ≡ n (mod p)
 * We assume group order = p-1 (g is a primitive root).
 * m = ceil(sqrt(p-1))
 * Baby steps: store (g^j, j) for j = 0..m-1
 * Giant steps: compute n * (g^(-m))^i for i = 0..m
 *   if match found => x = i*m + j
 */
static long long bsgs(u64 g, u64 p, u64 n) {
    if (n == 1) return 0; /* g^0 = 1 */

    u64 order = p - 1; /* assume full group */
    u64 m = (u64)ceil(sqrt((double)order)) + 1;

    printf("[BSGS] m = %llu  (baby/giant steps each)\n", (unsigned long long)m);

    if (m > 2000000ULL) {
        printf("[WARN] m=%llu is very large – this may use a lot of RAM and time.\n",
               (unsigned long long)m);
    }

    ht_init((size_t)m);

    /* Baby steps: compute g^j mod p, store */
    u64 gj = 1;
    for (u64 j = 0; j < m; j++) {
        ht_insert(gj, j);
        gj = mulmod(gj, g, p);
    }

    /* Giant step factor: g^(-m) mod p */
    u64 gm   = powmod(g, m, p);
    u64 gm_inv = modinv(gm, p);
    if (gm_inv == (u64)-1) {
        printf("[ERR] Could not compute modular inverse.\n");
        ht_free(); return -1;
    }

    /* Giant steps */
    u64 gamma = n; /* n * (g^-m)^0 */
    long long result = -1;
    for (u64 i = 0; i <= m; i++) {
        u64 j = ht_lookup(gamma);
        if (j != (u64)-1) {
            result = (long long)(i * m + j);
            break;
        }
        gamma = mulmod(gamma, gm_inv, p);
    }

    ht_free();
    return result;
}

int main(int argc, char *argv[]) {
    u64 g, p, n;

    if (argc == 4) {
        g = strtoull(argv[1], NULL, 10);
        p = strtoull(argv[2], NULL, 10);
        n = strtoull(argv[3], NULL, 10);
    } else {
        printf("=== BSGS Discrete Log Attacker ===\n");
        printf("Enter values captured from Wireshark:\n");
        printf("  g (generator) : "); scanf("%llu", &g);
        printf("  p (prime)     : "); scanf("%llu", &p);
        printf("  n (public key): "); scanf("%llu", &n);
    }

    printf("\n[*] Input:\n");
    printf("    g = %llu\n", (unsigned long long)g);
    printf("    p = %llu\n", (unsigned long long)p);
    printf("    n = %llu\n", (unsigned long long)n);

    /* Validate */
    if (!is_prime(p)) {
        printf("[WARN] p=%llu does not appear to be prime!\n", (unsigned long long)p);
    }
    if (g >= p || n >= p) {
        printf("[ERR] g and n must be < p.\n"); return 1;
    }

    u64 order_estimate = p - 1;
    double bits = log2((double)order_estimate);
    printf("[*] Group order ~ 2^%.1f\n", bits);
    if (bits > 40) {
        printf("[WARN] Group order > 2^40. BSGS needs O(sqrt(p)) space and time.\n"
               "       This may be infeasible. Consider small p only.\n");
    }

    printf("[*] Launching Baby-Step Giant-Step attack...\n\n");
    clock_t t0 = clock();
    long long x = bsgs(g, p, n);
    double elapsed = (double)(clock() - t0) / CLOCKS_PER_SEC;

    if (x >= 0) {
        printf("\n[SUCCESS] Private key x = %lld\n", x);
        /* verify */
        u64 check = powmod(g, (u64)x, p);
        printf("[VERIFY] g^x mod p = %llu  (expected %llu) %s\n",
               (unsigned long long)check,
               (unsigned long long)n,
               check == n ? "✓ CORRECT" : "✗ WRONG");
    } else {
        printf("\n[FAIL] Could not find discrete log in the given range.\n");
    }
    printf("[TIME] %.4f seconds\n", elapsed);
    return (x < 0) ? 1 : 0;
}
