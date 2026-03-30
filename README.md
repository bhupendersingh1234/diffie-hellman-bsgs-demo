# Diffie-Hellman Key Exchange — Security Demo with BSGS Attack

A complete implementation of the **Diffie-Hellman key exchange protocol** with a **Baby-Step Giant-Step (BSGS) discrete logarithm attack**, demonstrating the difference between insecure (small prime) and secure (large prime) DH parameters.

Built from scratch in **C** (server, client, attacker) and **Python** (GUI demo) — no cryptographic libraries used.

---

## 📁 Project Structure

```
dh_project/
├── c_code/
│   ├── dh_server.c       # DH Server — generates parameters, sends public key
│   ├── dh_client.c       # DH Client — receives params, computes shared secret
│   └── bsgs_attack.c     # BSGS Attacker — cracks private key from public values
└── python_code/
    └── dh_gui.py         # GUI Demo — visual comparison of secure vs insecure DH
```

---

## ⚙️ Required Software

### For C programs (Windows):
- [MSYS2](https://www.msys2.org/) with MinGW-w64 GCC

Install GCC inside MSYS2 MINGW64 terminal:
```bash
pacman -S mingw-w64-x86_64-gcc
```

### For Python GUI:
- [Python 3.x](https://www.python.org/downloads/)
- `tkinter` — comes built-in with Python, no extra install needed

---

## 🔧 Compilation (C Programs)

Open **MSYS2 MINGW64** terminal and navigate to the `c_code` folder:

```bash
cd /c/Users/<your-username>/Desktop/assignments/crypto\ theory/dh_project/c_code
```

Compile all three files:

```bash
gcc -O2 -o dh_server dh_server.c -lws2_32
gcc -O2 -o dh_client dh_client.c -lws2_32
gcc -O2 -o bsgs_attack bsgs_attack.c -lm
```

> `-lws2_32` links the Windows Socket library required for networking.  
> `-lm` links the math library required by the BSGS attacker.

---

## ▶️ How to Run

### Option A — Python GUI (Recommended)

Open **Command Prompt** and run:

```cmd
cd "C:\Users\<your-username>\Desktop\assignments\crypto theory\dh_project\python_code"
python dh_gui.py
```

A window opens with three buttons:
| Button | What it does |
|---|---|
| **Run Not-Secure** | Uses small primes → BSGS cracks the key ✅ |
| **Run Secure** | Uses large primes → BSGS fails 🔒 |
| **Run Both** | Full comparison with analysis report |

---

### Option B — Manual C Programs (3 terminals)

> **Order matters — always start the server first.**

**Terminal 1 — Start the Server:**
```bash
./dh_server
```
Server prints `g`, `p`, and public key `A`, then waits for a client.

**Terminal 2 — Connect the Client:**
```bash
./dh_client
```
Client connects, exchanges public keys, both sides compute the shared secret.

**Terminal 3 — Run the BSGS Attack:**
```bash
./bsgs_attack 5 23 8
```
Replace `5 23 8` with the actual `g p A` values printed by the server.

Expected output:
```
[SUCCESS] Private key x = 6
[VERIFY]  g^x mod p = 8  (expected 8) ✓ CORRECT
```

---

## 🔐 How It Works

### Diffie-Hellman Key Exchange
1. Server picks a prime `p`, generator `g`, and private key `a`. Computes public key `A = g^a mod p`
2. Server sends `g`, `p`, `A` to client **in plaintext**
3. Client picks private key `b`, computes `B = g^b mod p`, sends `B` to server
4. Both compute shared secret: `S = A^b mod p = B^a mod p = g^(ab) mod p`

### BSGS Attack (Baby-Step Giant-Step)
- An attacker who captures `g`, `p`, `A` from the network can solve `g^x ≡ A (mod p)` for the private key `x`
- Time complexity: **O(√p)** — feasible for small primes, infeasible for 256-bit+ primes
- The GUI demonstrates both cases side by side

### Why Small Primes Are Insecure
| Parameter Size | BSGS Attack | Result |
|---|---|---|
| p ≤ 2^20 (small) | Succeeds in milliseconds | 🔓 Key cracked |
| p ≥ 2^256 (large) | Times out (centuries) | 🔒 Key safe |

---

## 📌 Notes
- This is a **teaching/demo project** — parameters are intentionally small for the insecure mode
- The server uses fixed demo values (`p=23, g=5, a=6`) so Wireshark capture is reproducible
- All modular arithmetic implemented manually using fast exponentiation and extended Euclidean algorithm
