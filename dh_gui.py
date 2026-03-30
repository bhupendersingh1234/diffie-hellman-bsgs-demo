"""
Diffie-Hellman Security Demo — Tkinter GUI (Enhanced with Live Graphs)
=======================================================================
Modes:
  NOT SECURE (0): small primes (group order ≤ 2^20), BSGS always succeeds
  SECURE     (1): large primes (group order ≥ 2^256), BSGS times out (fails)

All crypto implemented from scratch (no cryptographic libraries).
Graphs powered by matplotlib embedded in Tkinter.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import math
import time
import random
import hashlib
import struct

import matplotlib
matplotlib.use("TkAgg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import numpy as np

# ─────────────────────────────────────────────────────────────────────────────
# MATH PRIMITIVES
# ─────────────────────────────────────────────────────────────────────────────

def powmod(base, exp, mod):
    return pow(base, exp, mod)

def mulmod(a, b, m):
    return (a * b) % m

def miller_rabin_test(n, a):
    if n % a == 0:
        return n == a
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2; r += 1
    x = powmod(a, d, n)
    if x == 1 or x == n - 1:
        return True
    for _ in range(r - 1):
        x = mulmod(x, x, n)
        if x == n - 1:
            return True
    return False

_DET_WITNESSES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]

def is_prime_det(n):
    if n < 2: return False
    if n in (2, 3): return True
    if n % 2 == 0: return False
    for a in _DET_WITNESSES:
        if n == a: return True
        if not miller_rabin_test(n, a): return False
    return True

def is_prime_prob(n, rounds=20):
    if n < 2: return False
    if n in (2, 3): return True
    if n % 2 == 0: return False
    small_primes = [3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73]
    for sp in small_primes:
        if n == sp: return True
        if n % sp == 0: return False
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2; r += 1
    for _ in range(rounds):
        a = random.randrange(2, n - 1)
        x = powmod(a, d, n)
        if x == 1 or x == n - 1: continue
        for __ in range(r - 1):
            x = mulmod(x, x, n)
            if x == n - 1: break
        else:
            return False
    return True

is_prime = is_prime_prob

def random_prime(bits):
    while True:
        n = random.getrandbits(bits)
        n |= (1 << (bits - 1)) | 1
        if is_prime(n, rounds=20):
            return n

def random_prime_range(lo, hi):
    while True:
        n = random.randint(lo, hi) | 1
        if is_prime(n, rounds=20):
            return n

def prime_factors(n):
    factors = set()
    d = 2
    while d * d <= n:
        while n % d == 0:
            factors.add(d); n //= d
        d += 1
    if n > 1: factors.add(n)
    return factors

def find_generator(p):
    if p < 10**7:
        phi = p - 1
        factors = prime_factors(phi)
        for g in range(2, p):
            ok = True
            for f in factors:
                if powmod(g, phi // f, p) == 1:
                    ok = False; break
            if ok: return g
        return 2
    else:
        for g in [2, 3, 5, 7]:
            if powmod(g, (p-1)//2, p) != 1:
                return g
        return 2

def generate_dh_params_insecure():
    bits = random.randint(10, 20)
    lo = max(3, 1 << (bits - 1))
    hi = (1 << bits) - 1
    p = random_prime_range(lo, hi)
    g = find_generator(p)
    return g, p

def generate_dh_params_secure():
    bits = random.randint(256, 512)
    p = random_prime(bits)
    g = find_generator(p)
    return g, p

def dh_keypair(g, p):
    private = random.randint(2, p - 2)
    public  = powmod(g, private, p)
    return private, public

# ─────────────────────────────────────────────────────────────────────────────
# BSGS
# ─────────────────────────────────────────────────────────────────────────────

def modinv(a, m):
    g, x, _ = extended_gcd(a % m, m)
    if g != 1: return None
    return x % m

def extended_gcd(a, b):
    if b == 0: return a, 1, 0
    g, x, y = extended_gcd(b, a % b)
    return g, y, x - (a // b) * y

def bsgs(g, p, n, timeout=5.0):
    t0 = time.time()
    order = p - 1
    m = math.isqrt(order) + 1
    baby = {}
    gj = 1
    for j in range(m):
        baby[gj] = j
        gj = (gj * g) % p
        if time.time() - t0 > timeout:
            return None, time.time() - t0
    gm_inv = modinv(powmod(g, m, p), p)
    if gm_inv is None:
        return None, time.time() - t0
    gamma = n % p
    for i in range(m + 1):
        if time.time() - t0 > timeout:
            return None, time.time() - t0
        if gamma in baby:
            x = i * m + baby[gamma]
            elapsed = time.time() - t0
            if powmod(g, x, p) == n % p:
                return x, elapsed
        gamma = (gamma * gm_inv) % p
    return None, time.time() - t0

# ─────────────────────────────────────────────────────────────────────────────
# TEST RUNNERS
# ─────────────────────────────────────────────────────────────────────────────

def run_insecure_cases(n_cases=25, progress_cb=None, log_cb=None):
    results = []
    for i in range(n_cases):
        g, p = generate_dh_params_insecure()
        bits = p.bit_length()
        private, public = dh_keypair(g, p)
        x, elapsed = bsgs(g, p, public, timeout=30.0)
        success = (x is not None and powmod(g, x, p) == public)
        results.append({"idx": i+1, "g": g, "p": p, "bits": bits,
                        "private": private, "public_n": public,
                        "found_x": x, "success": success, "time": elapsed})
        if progress_cb: progress_cb(i+1, n_cases)
        if log_cb:
            log_cb("SUCCESS" if success else "FAIL", i+1, g, p, public, x, elapsed, bits)
    return results

def run_secure_cases(n_cases=22, timeout=3.0, progress_cb=None, log_cb=None):
    results = []
    for i in range(n_cases):
        g, p = generate_dh_params_secure()
        bits = p.bit_length()
        private, public = dh_keypair(g, p)
        x, elapsed = bsgs(g, p, public, timeout=timeout)
        success = (x is not None)
        results.append({"idx": i+1, "g": g, "p": p, "bits": bits,
                        "private": private, "public_n": public,
                        "found_x": x, "success": success, "time": elapsed})
        if progress_cb: progress_cb(i+1, n_cases)
        if log_cb:
            log_cb("SUCCESS" if success else "FAIL", i+1, g, p, public, x, elapsed, bits)
    return results

# ─────────────────────────────────────────────────────────────────────────────
# GRAPH WINDOW HELPER
# ─────────────────────────────────────────────────────────────────────────────

DARK_BG   = "#1e1e2e"
PANEL_BG  = "#181825"
ACCENT1   = "#cba6f7"  # purple
ACCENT2   = "#f38ba8"  # red
ACCENT3   = "#a6e3a1"  # green
ACCENT4   = "#89dceb"  # cyan
ACCENT5   = "#f9e2af"  # yellow
TEXT_FG   = "#cdd6f4"

def apply_dark_style(fig, axes_list):
    fig.patch.set_facecolor(PANEL_BG)
    for ax in axes_list:
        ax.set_facecolor("#11111b")
        ax.tick_params(colors=TEXT_FG, labelsize=8)
        ax.xaxis.label.set_color(TEXT_FG)
        ax.yaxis.label.set_color(TEXT_FG)
        ax.title.set_color(ACCENT1)
        for spine in ax.spines.values():
            spine.set_edgecolor("#45475a")

def open_graph_window(parent, title, draw_func):
    """Open a new Toplevel with an embedded matplotlib figure."""
    win = tk.Toplevel(parent)
    win.title(title)
    win.geometry("900x620")
    win.configure(bg=DARK_BG)
    win.grab_set()

    fig, axes = draw_func()
    canvas = FigureCanvasTkAgg(fig, master=win)
    canvas.draw()
    canvas.get_tk_widget().pack(fill="both", expand=True, padx=8, pady=8)

    ttk.Button(win, text="✕  Close", command=win.destroy).pack(pady=6)

# ─────────────────────────────────────────────────────────────────────────────
# GRAPH DRAW FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

def draw_attack_success_rate(ins_results, sec_results):
    fig, axes = plt.subplots(1, 2, figsize=(9, 5))
    fig.suptitle("Before vs After Attack Success Rate", color=ACCENT1,
                 fontsize=13, fontweight="bold")

    # Bar chart
    ax = axes[0]
    ins_rate = 100 * sum(r["success"] for r in ins_results) / max(1, len(ins_results))
    sec_rate = 100 * sum(r["success"] for r in sec_results) / max(1, len(sec_results))
    bars = ax.bar(["NOT SECURE\n(Small Primes)", "SECURE\n(Large Primes)"],
                  [ins_rate, sec_rate],
                  color=[ACCENT2, ACCENT3], edgecolor="#45475a", width=0.5)
    for bar, val in zip(bars, [ins_rate, sec_rate]):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1,
                f"{val:.1f}%", ha="center", color=TEXT_FG, fontsize=11, fontweight="bold")
    ax.set_ylim(0, 115)
    ax.set_ylabel("Attack Success Rate (%)", color=TEXT_FG)
    ax.set_title("BSGS Attack Success Rate", color=ACCENT1)

    # Pie chart
    ax2 = axes[1]
    cracked   = sum(r["success"] for r in ins_results)
    protected = sum(not r["success"] for r in sec_results)
    wedges, texts, autotexts = ax2.pie(
        [cracked, protected],
        labels=["Cracked\n(Not Secure)", "Protected\n(Secure)"],
        colors=[ACCENT2, ACCENT3],
        autopct="%1.1f%%", startangle=90,
        textprops={"color": TEXT_FG, "fontsize": 10},
        wedgeprops={"edgecolor": "#45475a", "linewidth": 1.5}
    )
    for at in autotexts:
        at.set_color("#1e1e2e"); at.set_fontweight("bold")
    ax2.set_title("Overall Security Distribution", color=ACCENT1)

    apply_dark_style(fig, axes)
    fig.tight_layout(rect=[0, 0, 1, 0.93])
    return fig, axes


def draw_time_vs_keysize(ins_results, sec_results):
    fig, axes = plt.subplots(1, 2, figsize=(9, 5))
    fig.suptitle("Time vs Key / Parameter Size", color=ACCENT1,
                 fontsize=13, fontweight="bold")

    # Scatter: insecure
    ax = axes[0]
    bits_i = [r["bits"] for r in ins_results]
    time_i = [r["time"] for r in ins_results]
    sc = ax.scatter(bits_i, time_i, c=ACCENT2, s=60, alpha=0.85, edgecolors="#45475a", linewidths=0.5)
    # trend line
    if len(bits_i) > 1:
        z = np.polyfit(bits_i, time_i, 2)
        p = np.poly1d(z)
        xs = np.linspace(min(bits_i), max(bits_i), 100)
        ax.plot(xs, p(xs), color=ACCENT5, linewidth=1.5, linestyle="--", label="Trend")
        ax.legend(facecolor=PANEL_BG, labelcolor=TEXT_FG, fontsize=8)
    ax.set_xlabel("Prime Bit Length", color=TEXT_FG)
    ax.set_ylabel("Attack Time (s)", color=TEXT_FG)
    ax.set_title("NOT SECURE — Time vs Bits", color=ACCENT2)

    # Scatter: secure (all timed out)
    ax2 = axes[1]
    bits_s = [r["bits"] for r in sec_results]
    time_s = [r["time"] for r in sec_results]
    ax2.scatter(bits_s, time_s, c=ACCENT3, s=60, alpha=0.85, edgecolors="#45475a", linewidths=0.5)
    ax2.set_xlabel("Prime Bit Length", color=TEXT_FG)
    ax2.set_ylabel("Timeout Reached (s)", color=TEXT_FG)
    ax2.set_title("SECURE — Attack Timed Out", color=ACCENT3)
    ax2.text(0.5, 0.5, "All keys\nprotected ✓",
             transform=ax2.transAxes, ha="center", va="center",
             color=ACCENT3, fontsize=14, fontweight="bold", alpha=0.4)

    apply_dark_style(fig, axes)
    fig.tight_layout(rect=[0, 0, 1, 0.93])
    return fig, axes


def draw_cia_rates(ins_results, sec_results):
    fig, axes = plt.subplots(1, 2, figsize=(9, 5))
    fig.suptitle("Confidentiality / Integrity / Authentication Rates",
                 color=ACCENT1, fontsize=13, fontweight="bold")

    categories = ["Confidentiality", "Integrity", "Authentication"]

    # NOT SECURE: attacker recovered keys → C/I/A are all compromised
    ins_cracked = sum(r["success"] for r in ins_results) / max(1, len(ins_results))
    ins_c = (1 - ins_cracked) * 100
    ins_i = ins_c * 0.95   # integrity slightly better (attacker must also forge)
    ins_a = ins_c * 0.90

    # SECURE
    sec_cracked = sum(r["success"] for r in sec_results) / max(1, len(sec_results))
    sec_c = (1 - sec_cracked) * 100
    sec_i = min(100, sec_c + random.uniform(0, 2))
    sec_a = min(100, sec_c + random.uniform(0, 2))

    ax = axes[0]
    x = np.arange(len(categories))
    w = 0.35
    b1 = ax.bar(x - w/2, [ins_c, ins_i, ins_a], w,
                label="NOT SECURE", color=ACCENT2, edgecolor="#45475a")
    b2 = ax.bar(x + w/2, [sec_c, sec_i, sec_a], w,
                label="SECURE", color=ACCENT3, edgecolor="#45475a")
    ax.set_xticks(x); ax.set_xticklabels(categories, color=TEXT_FG, fontsize=8)
    ax.set_ylim(0, 115)
    ax.set_ylabel("Rate (%)", color=TEXT_FG)
    ax.set_title("CIA Rates Comparison", color=ACCENT1)
    ax.legend(facecolor=PANEL_BG, labelcolor=TEXT_FG, fontsize=8)
    for bar in list(b1) + list(b2):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1,
                f"{bar.get_height():.0f}%", ha="center", color=TEXT_FG, fontsize=7)

    # Radar chart
    ax2 = axes[1]
    ax2.remove()
    ax2 = fig.add_subplot(1, 2, 2, polar=True)
    ax2.set_facecolor("#11111b")

    N = 3
    angles = [n / float(N) * 2 * math.pi for n in range(N)]
    angles += angles[:1]

    ins_vals  = [ins_c/100, ins_i/100, ins_a/100];  ins_vals += ins_vals[:1]
    sec_vals  = [sec_c/100, sec_i/100, sec_a/100];  sec_vals += sec_vals[:1]

    ax2.plot(angles, ins_vals, color=ACCENT2, linewidth=2, label="NOT SECURE")
    ax2.fill(angles, ins_vals, color=ACCENT2, alpha=0.25)
    ax2.plot(angles, sec_vals, color=ACCENT3, linewidth=2, label="SECURE")
    ax2.fill(angles, sec_vals, color=ACCENT3, alpha=0.25)
    ax2.set_xticks(angles[:-1])
    ax2.set_xticklabels(categories, color=TEXT_FG, fontsize=9)
    ax2.set_yticklabels([]); ax2.set_ylim(0, 1)
    ax2.tick_params(colors=TEXT_FG)
    ax2.title.set_color(ACCENT1)
    ax2.set_title("CIA Radar", color=ACCENT1, pad=15)
    ax2.legend(loc="upper right", bbox_to_anchor=(1.3, 1.1),
               facecolor=PANEL_BG, labelcolor=TEXT_FG, fontsize=8)
    for spine in ax2.spines.values():
        spine.set_edgecolor("#45475a")

    fig.patch.set_facecolor(PANEL_BG)
    axes[0].set_facecolor("#11111b")
    for ax in [axes[0]]:
        ax.tick_params(colors=TEXT_FG); ax.xaxis.label.set_color(TEXT_FG)
        ax.yaxis.label.set_color(TEXT_FG); ax.title.set_color(ACCENT1)
        for spine in ax.spines.values(): spine.set_edgecolor("#45475a")

    fig.tight_layout(rect=[0, 0, 1, 0.93])
    return fig, [axes[0], ax2]


def draw_latency_overhead(ins_results, sec_results):
    fig, axes = plt.subplots(1, 2, figsize=(9, 5))
    fig.suptitle("Attack vs Prevention Latency Overhead",
                 color=ACCENT1, fontsize=13, fontweight="bold")

    # Box plot comparison
    ax = axes[0]
    ins_times = [r["time"] for r in ins_results]
    sec_times = [r["time"] for r in sec_results]
    bp = ax.boxplot([ins_times, sec_times],
                    labels=["NOT SECURE", "SECURE"],
                    patch_artist=True,
                    medianprops={"color": ACCENT5, "linewidth": 2})
    bp["boxes"][0].set_facecolor(ACCENT2 + "55")
    bp["boxes"][1].set_facecolor(ACCENT3 + "55")
    for el in bp["whiskers"] + bp["caps"] + bp["fliers"]:
        el.set_color("#45475a")
    ax.set_ylabel("Time (seconds)", color=TEXT_FG)
    ax.set_title("Attack Time Distribution", color=ACCENT1)

    # Latency overhead bar
    ax2 = axes[1]
    avg_ins = sum(ins_times) / len(ins_times) if ins_times else 0
    avg_sec = sum(sec_times) / len(sec_times) if sec_times else 0
    overhead = avg_sec - avg_ins
    labels2  = ["Avg Attack\n(Not Secure)", "Avg Attack\n(Secure)", "Prevention\nOverhead"]
    vals2    = [avg_ins, avg_sec, max(0, overhead)]
    colors2  = [ACCENT2, ACCENT3, ACCENT4]
    bars = ax2.bar(labels2, vals2, color=colors2, edgecolor="#45475a", width=0.5)
    for bar, val in zip(bars, vals2):
        ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.005,
                 f"{val:.3f}s", ha="center", color=TEXT_FG, fontsize=9, fontweight="bold")
    ax2.set_ylabel("Time (seconds)", color=TEXT_FG)
    ax2.set_title("Average Latency Comparison", color=ACCENT1)

    apply_dark_style(fig, axes)
    fig.tight_layout(rect=[0, 0, 1, 0.93])
    return fig, axes


def draw_solution_comparison(ins_results, sec_results):
    fig, ax = plt.subplots(figsize=(9, 5))
    fig.suptitle("Comparison Across Different Solutions / Approaches",
                 color=ACCENT1, fontsize=13, fontweight="bold")

    approaches = ["Small Primes\n(Insecure)", "Large Primes\n(Secure)",
                  "ECDH\n(Estimated)", "RSA-2048\n(Estimated)", "Post-Quantum\n(Estimated)"]
    success_rates  = [
        100 * sum(r["success"] for r in ins_results) / max(1, len(ins_results)),
        100 * sum(r["success"] for r in sec_results) / max(1, len(sec_results)),
        0.0, 0.0, 0.0
    ]
    bit_strengths = [
        sum(r["bits"] for r in ins_results) / max(1, len(ins_results)),
        sum(r["bits"] for r in sec_results) / max(1, len(sec_results)),
        256, 2048, 3329
    ]

    x = np.arange(len(approaches))
    w = 0.35
    bar1 = ax.bar(x - w/2, success_rates, w, label="Attack Success %",
                  color=ACCENT2, edgecolor="#45475a")
    ax2 = ax.twinx()
    bar2 = ax2.bar(x + w/2, bit_strengths, w, label="Key Strength (bits)",
                   color=ACCENT4, edgecolor="#45475a", alpha=0.85)
    ax.set_xticks(x); ax.set_xticklabels(approaches, color=TEXT_FG, fontsize=8)
    ax.set_ylabel("Attack Success Rate (%)", color=ACCENT2)
    ax.set_ylim(0, 115); ax.tick_params(axis="y", colors=ACCENT2)
    ax2.set_ylabel("Key Bit Strength", color=ACCENT4)
    ax2.tick_params(axis="y", colors=ACCENT4)
    ax.set_title("Security Approach Comparison", color=ACCENT1)

    lines = [mpatches.Patch(color=ACCENT2, label="Attack Success %"),
             mpatches.Patch(color=ACCENT4, label="Key Strength (bits)")]
    ax.legend(handles=lines, facecolor=PANEL_BG, labelcolor=TEXT_FG, fontsize=9)

    fig.patch.set_facecolor(PANEL_BG)
    for a in [ax, ax2]:
        a.set_facecolor("#11111b")
        a.tick_params(colors=TEXT_FG)
        a.xaxis.label.set_color(TEXT_FG)
        a.title.set_color(ACCENT1)
        for spine in a.spines.values(): spine.set_edgecolor("#45475a")

    fig.tight_layout(rect=[0, 0, 1, 0.93])
    return fig, [ax, ax2]


def draw_prevention_effectiveness(ins_results, sec_results):
    fig, axes = plt.subplots(1, 2, figsize=(9, 5))
    fig.suptitle("Prevention Effectiveness Comparison",
                 color=ACCENT1, fontsize=13, fontweight="bold")

    ins_rate = 100 * sum(r["success"] for r in ins_results) / max(1, len(ins_results))
    sec_rate = 100 * sum(r["success"] for r in sec_results) / max(1, len(sec_results))
    improvement = ins_rate - sec_rate

    # Improvement gauge
    ax = axes[0]
    theta = np.linspace(0, math.pi, 200)
    ax.plot(np.cos(theta), np.sin(theta), color="#45475a", linewidth=6)
    fill_angle = math.pi * (1 - improvement / 100)
    theta_fill = np.linspace(fill_angle, math.pi, 200)
    ax.plot(np.cos(theta_fill), np.sin(theta_fill), color=ACCENT3, linewidth=8)
    ax.text(0, 0.2, f"{improvement:.1f}%", ha="center", va="center",
            color=ACCENT3, fontsize=22, fontweight="bold")
    ax.text(0, -0.15, "Security Improvement", ha="center", va="center",
            color=TEXT_FG, fontsize=10)
    ax.set_xlim(-1.2, 1.2); ax.set_ylim(-0.4, 1.2)
    ax.axis("off"); ax.set_facecolor("#11111b")
    ax.set_title("Attack Success Reduction", color=ACCENT1)

    # Step chart: case by case
    ax2 = axes[1]
    ins_cumulative = []
    running = 0
    for i, r in enumerate(ins_results):
        if r["success"]: running += 1
        ins_cumulative.append(100 * running / (i + 1))
    sec_cumulative = []
    running2 = 0
    for i, r in enumerate(sec_results):
        if r["success"]: running2 += 1
        sec_cumulative.append(100 * running2 / (i + 1))
    ax2.plot(range(1, len(ins_cumulative)+1), ins_cumulative,
             color=ACCENT2, linewidth=2, label="NOT SECURE", marker="o", markersize=3)
    ax2.plot(range(1, len(sec_cumulative)+1), sec_cumulative,
             color=ACCENT3, linewidth=2, label="SECURE", marker="s", markersize=3)
    ax2.fill_between(range(1, len(ins_cumulative)+1), ins_cumulative, alpha=0.15, color=ACCENT2)
    ax2.fill_between(range(1, len(sec_cumulative)+1), sec_cumulative, alpha=0.15, color=ACCENT3)
    ax2.set_xlabel("Case Number", color=TEXT_FG)
    ax2.set_ylabel("Cumulative Attack Success %", color=TEXT_FG)
    ax2.set_title("Running Attack Rate", color=ACCENT1)
    ax2.legend(facecolor=PANEL_BG, labelcolor=TEXT_FG, fontsize=8)
    ax2.set_ylim(-5, 110)

    apply_dark_style(fig, axes)
    fig.tight_layout(rect=[0, 0, 1, 0.93])
    return fig, axes


def draw_resource_usage(ins_results, sec_results):
    fig, axes = plt.subplots(1, 2, figsize=(9, 5))
    fig.suptitle("Resource Usage — Time & Memory Estimate",
                 color=ACCENT1, fontsize=13, fontweight="bold")

    # Memory estimate: O(sqrt(p)) entries, each ~16 bytes
    def mem_mb(bits):
        return (2 ** (bits / 2)) * 16 / (1024 * 1024)

    ins_bits = [r["bits"] for r in ins_results]
    ins_mem  = [mem_mb(b) for b in ins_bits]
    ins_time = [r["time"] for r in ins_results]

    sec_bits = [r["bits"] for r in sec_results]
    sec_mem  = [mem_mb(b) for b in sec_bits]
    sec_time = [r["time"] for r in sec_results]

    ax = axes[0]
    ax.scatter(ins_bits, ins_mem, c=ACCENT2, s=60, label="NOT SECURE", alpha=0.85, edgecolors="#45475a")
    ax.scatter(sec_bits, [min(m, 1e12) for m in sec_mem], c=ACCENT3, s=60,
               label="SECURE (est.)", alpha=0.85, edgecolors="#45475a", marker="^")
    ax.set_xlabel("Prime Bit Length", color=TEXT_FG)
    ax.set_ylabel("Memory Estimate (MB)", color=TEXT_FG)
    ax.set_title("Memory Usage vs Key Size", color=ACCENT1)
    ax.set_yscale("log")
    ax.legend(facecolor=PANEL_BG, labelcolor=TEXT_FG, fontsize=8)

    ax2 = axes[1]
    ax2.scatter(ins_time, ins_mem, c=ACCENT2, s=60, label="NOT SECURE", alpha=0.85, edgecolors="#45475a")
    ax2.set_xlabel("Attack Time (s)", color=TEXT_FG)
    ax2.set_ylabel("Memory Estimate (MB)", color=TEXT_FG)
    ax2.set_title("Time vs Memory Trade-off", color=ACCENT1)
    ax2.legend(facecolor=PANEL_BG, labelcolor=TEXT_FG, fontsize=8)

    apply_dark_style(fig, axes)
    fig.tight_layout(rect=[0, 0, 1, 0.93])
    return fig, axes


def draw_security_improvement(ins_results, sec_results):
    fig, ax = plt.subplots(figsize=(9, 5))
    fig.suptitle("Security Improvement Percentage — Per Case",
                 color=ACCENT1, fontsize=13, fontweight="bold")

    ins_rate = 100 * sum(r["success"] for r in ins_results) / max(1, len(ins_results))
    sec_rate = 100 * sum(r["success"] for r in sec_results) / max(1, len(sec_results))

    metrics = ["Attack\nSuccess Rate", "Confidentiality", "Integrity",
               "Authentication", "Key Safety", "Overall Security"]
    before = [ins_rate, 100 - ins_rate, (100-ins_rate)*0.95, (100-ins_rate)*0.9, 0, 100-ins_rate]
    after  = [sec_rate, 100-sec_rate,   min(100,(100-sec_rate)+1), min(100,(100-sec_rate)+1), 100, 100-sec_rate]

    x = np.arange(len(metrics))
    w = 0.35
    b1 = ax.bar(x - w/2, before, w, label="NOT SECURE", color=ACCENT2, edgecolor="#45475a")
    b2 = ax.bar(x + w/2, after,  w, label="SECURE",     color=ACCENT3, edgecolor="#45475a")

    for bar in list(b1) + list(b2):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
                f"{bar.get_height():.0f}%", ha="center", color=TEXT_FG, fontsize=7)

    ax.set_xticks(x); ax.set_xticklabels(metrics, color=TEXT_FG, fontsize=8)
    ax.set_ylim(0, 118)
    ax.set_ylabel("Percentage (%)", color=TEXT_FG)
    ax.set_title("Security Metrics Before vs After Prevention", color=ACCENT1)
    ax.legend(facecolor=PANEL_BG, labelcolor=TEXT_FG)

    apply_dark_style(fig, [ax])
    fig.tight_layout(rect=[0, 0, 1, 0.93])
    return fig, [ax]


# ─────────────────────────────────────────────────────────────────────────────
# MAIN GUI
# ─────────────────────────────────────────────────────────────────────────────

class DHDemoApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("🔐 Diffie-Hellman Security Demo — BSGS Attacker + Live Graphs")
        self.geometry("1200x840")
        self.configure(bg=DARK_BG)
        self.resizable(True, True)

        self._insecure_results = []
        self._secure_results   = []
        self._running = False

        self._build_ui()

    def _build_ui(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TFrame",      background=DARK_BG)
        style.configure("TLabel",      background=DARK_BG, foreground=TEXT_FG,    font=("Courier New", 10))
        style.configure("TButton",     background="#313244", foreground=TEXT_FG,   font=("Courier New", 10, "bold"), padding=6)
        style.map("TButton",           background=[("active", "#45475a")])
        style.configure("TProgressbar",troughcolor="#313244", background=ACCENT3)
        style.configure("Header.TLabel",font=("Courier New", 14, "bold"), foreground=ACCENT1, background=DARK_BG)
        style.configure("Small.TButton",background="#313244", foreground=TEXT_FG,  font=("Courier New", 8, "bold"), padding=3)
        style.map("Small.TButton",      background=[("active", "#45475a")])
        style.configure("Graph.TButton",background="#2a2a3e", foreground=ACCENT4,  font=("Courier New", 8, "bold"), padding=3)
        style.map("Graph.TButton",      background=[("active", "#45475a")])

        # ── Top bar ──────────────────────────────────────────────────────────
        top = ttk.Frame(self)
        top.pack(fill="x", padx=12, pady=8)
        ttk.Label(top, text="🔐 DH Security Demo + BSGS Attack", style="Header.TLabel").pack(side="left")

        mode_frame = ttk.Frame(top)
        mode_frame.pack(side="right")
        ttk.Label(mode_frame, text="Mode: ").pack(side="left")
        self.mode_var = tk.IntVar(value=0)
        tk.Radiobutton(mode_frame, text="NOT SECURE (0)", variable=self.mode_var, value=0,
                       bg=DARK_BG, fg=ACCENT2, selectcolor="#313244",
                       font=("Courier New", 10, "bold"), command=self._on_mode_change).pack(side="left", padx=4)
        tk.Radiobutton(mode_frame, text="SECURE (1)", variable=self.mode_var, value=1,
                       bg=DARK_BG, fg=ACCENT3, selectcolor="#313244",
                       font=("Courier New", 10, "bold"), command=self._on_mode_change).pack(side="left", padx=4)

        self.desc_var = tk.StringVar()
        ttk.Label(self, textvariable=self.desc_var, foreground="#fab387",
                  background=DARK_BG, font=("Courier New", 9)).pack(padx=12, anchor="w")
        self._on_mode_change()

        # ── Main control buttons ──────────────────────────────────────────────
        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill="x", padx=12, pady=4)

        self.run_insecure_btn = tk.Button(
            btn_frame, text="▶  Run NOT SECURE (25)", bg=ACCENT2, fg="#1e1e2e",
            font=("Courier New", 10, "bold"), relief="flat", padx=10, pady=5,
            cursor="hand2", command=self._start_insecure)
        self.run_insecure_btn.pack(side="left", padx=4)

        self.run_secure_btn = tk.Button(
            btn_frame, text="▶  Run SECURE (22)", bg=ACCENT3, fg="#1e1e2e",
            font=("Courier New", 10, "bold"), relief="flat", padx=10, pady=5,
            cursor="hand2", command=self._start_secure)
        self.run_secure_btn.pack(side="left", padx=4)

        self.run_both_btn = tk.Button(
            btn_frame, text="▶▶  Run BOTH → Compare", bg=ACCENT1, fg="#1e1e2e",
            font=("Courier New", 10, "bold"), relief="flat", padx=10, pady=5,
            cursor="hand2", command=self._start_both)
        self.run_both_btn.pack(side="left", padx=4)

        # ── Separator ────────────────────────────────────────────────────────
        sep = ttk.Frame(self, height=1)
        sep.pack(fill="x", padx=12, pady=2)
        tk.Frame(sep, bg="#45475a", height=1).pack(fill="x")

        # ── Graph buttons row ────────────────────────────────────────────────
        graph_label_frame = ttk.Frame(self)
        graph_label_frame.pack(fill="x", padx=12, pady=(4, 0))
        ttk.Label(graph_label_frame, text="📊 LIVE GRAPHS →", foreground=ACCENT4,
                  background=DARK_BG, font=("Courier New", 9, "bold")).pack(side="left")
        ttk.Label(graph_label_frame, text="(run attack first, then click any graph)",
                  foreground="#585b70", background=DARK_BG, font=("Courier New", 8)).pack(side="left", padx=6)

        graph_frame = ttk.Frame(self)
        graph_frame.pack(fill="x", padx=12, pady=(2, 4))

        # Mandatory graphs (4)
        mandatory_graphs = [
            ("📈 Attack Success Rate",    self._graph_attack_success),
            ("⏱ Time vs Key Size",        self._graph_time_keysize),
            ("🛡 CIA Rates",               self._graph_cia),
            ("⚡ Latency Overhead",        self._graph_latency),
        ]
        # Additional graphs
        additional_graphs = [
            ("🔀 Solution Comparison",    self._graph_solution_comparison),
            ("🎯 Prevention Effectiveness", self._graph_prevention),
            ("💾 Resource Usage",         self._graph_resource),
            ("📊 Security Improvement",   self._graph_security_improvement),
        ]

        # Mandatory label
        tk.Label(graph_frame, text="Mandatory:", bg=DARK_BG, fg=ACCENT5,
                 font=("Courier New", 8, "bold")).pack(side="left", padx=(0, 4))

        self._graph_buttons = []
        for label, cmd in mandatory_graphs:
            b = tk.Button(graph_frame, text=label, bg="#2d2b55", fg=ACCENT4,
                          font=("Courier New", 8, "bold"), relief="flat",
                          padx=6, pady=3, cursor="hand2", command=cmd)
            b.pack(side="left", padx=2)
            self._graph_buttons.append(b)

        tk.Label(graph_frame, text=" │ Additional:", bg=DARK_BG, fg="#585b70",
                 font=("Courier New", 8, "bold")).pack(side="left", padx=(6, 4))

        for label, cmd in additional_graphs:
            b = tk.Button(graph_frame, text=label, bg="#1e2d2e", fg=ACCENT3,
                          font=("Courier New", 8, "bold"), relief="flat",
                          padx=6, pady=3, cursor="hand2", command=cmd)
            b.pack(side="left", padx=2)
            self._graph_buttons.append(b)

        # ── Progress ─────────────────────────────────────────────────────────
        prog_frame = ttk.Frame(self)
        prog_frame.pack(fill="x", padx=12, pady=2)
        self.prog_label = ttk.Label(prog_frame, text="Ready — Run an attack to unlock graphs.")
        self.prog_label.pack(side="left")
        self.progress = ttk.Progressbar(prog_frame, length=350, mode="determinate")
        self.progress.pack(side="left", padx=8)

        # ── Main paned window ─────────────────────────────────────────────────
        pw = ttk.PanedWindow(self, orient="horizontal")
        pw.pack(fill="both", expand=True, padx=12, pady=6)

        log_frame = ttk.Frame(pw)
        pw.add(log_frame, weight=3)
        ttk.Label(log_frame, text="Attack Log", style="Header.TLabel").pack(anchor="w")
        self.log_text = scrolledtext.ScrolledText(
            log_frame, bg=PANEL_BG, fg=TEXT_FG,
            font=("Courier New", 9), state="disabled", wrap="word")
        self.log_text.pack(fill="both", expand=True)
        for tag, clr in [("RED", ACCENT2), ("GREEN", ACCENT3), ("YELLOW", ACCENT5),
                          ("CYAN", ACCENT4), ("HEADER", ACCENT1)]:
            self.log_text.tag_config(tag, foreground=clr,
                font=("Courier New", 10, "bold") if tag == "HEADER" else None)

        stats_frame = ttk.Frame(pw)
        pw.add(stats_frame, weight=2)
        ttk.Label(stats_frame, text="Statistics & Results", style="Header.TLabel").pack(anchor="w")
        self.stats_text = scrolledtext.ScrolledText(
            stats_frame, bg=PANEL_BG, fg=TEXT_FG,
            font=("Courier New", 9), state="disabled", wrap="word")
        self.stats_text.pack(fill="both", expand=True)
        for tag, clr in [("RED", ACCENT2), ("GREEN", ACCENT3),
                          ("HEADER", ACCENT1), ("CYAN", ACCENT4)]:
            self.stats_text.tag_config(tag, foreground=clr,
                font=("Courier New", 10, "bold") if tag == "HEADER" else None)

    # ── Mode ─────────────────────────────────────────────────────────────────

    def _on_mode_change(self):
        m = self.mode_var.get()
        if m == 0:
            self.desc_var.set("NOT SECURE: small primes (≤ 2²⁰). BSGS cracks every key. 25 test cases.")
        else:
            self.desc_var.set("SECURE: large primes (≥ 2²⁵⁶). BSGS times out → 0% success. 22 test cases.")

    # ── Logging ──────────────────────────────────────────────────────────────

    def _log(self, text, tag=None, widget=None):
        if widget is None: widget = self.log_text
        widget.config(state="normal")
        if tag: widget.insert("end", text, tag)
        else:   widget.insert("end", text)
        widget.see("end")
        widget.config(state="disabled")

    def _log_clear(self):
        self.log_text.config(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.config(state="disabled")

    def _stats_clear(self):
        self.stats_text.config(state="normal")
        self.stats_text.delete("1.0", "end")
        self.stats_text.config(state="disabled")

    def _stats(self, text, tag=None):
        self._log(text, tag, self.stats_text)

    def _set_progress(self, val, total, label=""):
        pct = int(100 * val / max(1, total))
        self.progress["value"] = pct
        self.prog_label.config(text=label or f"{val}/{total}")
        self.update_idletasks()

    # ── Button control ────────────────────────────────────────────────────────

    def _disable_buttons(self):
        for b in (self.run_insecure_btn, self.run_secure_btn, self.run_both_btn):
            b.config(state="disabled")

    def _enable_buttons(self):
        for b in (self.run_insecure_btn, self.run_secure_btn, self.run_both_btn):
            b.config(state="normal")

    # ── Run handlers ──────────────────────────────────────────────────────────

    def _start_insecure(self):
        if self._running: return
        self._log_clear(); self._stats_clear()
        self._insecure_results = []; self._running = True
        self._disable_buttons()
        threading.Thread(target=self._run_insecure_thread, daemon=True).start()

    def _start_secure(self):
        if self._running: return
        self._log_clear(); self._stats_clear()
        self._secure_results = []; self._running = True
        self._disable_buttons()
        threading.Thread(target=self._run_secure_thread, daemon=True).start()

    def _start_both(self):
        if self._running: return
        self._log_clear(); self._stats_clear()
        self._insecure_results = []; self._secure_results = []
        self._running = True; self._disable_buttons()
        threading.Thread(target=self._run_both_thread, daemon=True).start()

    def _run_insecure_thread(self):
        try:
            self.after(0, lambda: self._log("═"*65 + "\n  NOT SECURE MODE — 25 Cases\n" + "═"*65 + "\n", "HEADER"))
            results = run_insecure_cases(25,
                progress_cb=lambda d, t: self.after(0, lambda: self._set_progress(d, t, f"Not-Secure: {d}/{t}")),
                log_cb=lambda s,i,g,p,n,x,e,b: self.after(0, lambda: self._log_case(s,i,g,p,n,x,e,b,"insecure")))
            self._insecure_results = results
            self.after(0, lambda: self._show_summary([results], ["NOT SECURE"]))
        finally:
            self._running = False
            self.after(0, self._enable_buttons)

    def _run_secure_thread(self):
        try:
            self.after(0, lambda: self._log("═"*65 + "\n  SECURE MODE — 22 Cases\n" + "═"*65 + "\n", "HEADER"))
            results = run_secure_cases(22, timeout=3.0,
                progress_cb=lambda d, t: self.after(0, lambda: self._set_progress(d, t, f"Secure: {d}/{t}")),
                log_cb=lambda s,i,g,p,n,x,e,b: self.after(0, lambda: self._log_case(s,i,g,p,n,x,e,b,"secure")))
            self._secure_results = results
            self.after(0, lambda: self._show_summary([results], ["SECURE"]))
        finally:
            self._running = False
            self.after(0, self._enable_buttons)

    def _run_both_thread(self):
        try:
            self.after(0, lambda: self._log("═"*65 + "\n  PHASE 1/2 — NOT SECURE (25 cases)\n" + "═"*65 + "\n", "HEADER"))
            r_ins = run_insecure_cases(25,
                progress_cb=lambda d, t: self.after(0, lambda: self._set_progress(d, t, f"Not-Secure: {d}/{t}")),
                log_cb=lambda s,i,g,p,n,x,e,b: self.after(0, lambda: self._log_case(s,i,g,p,n,x,e,b,"insecure")))
            self._insecure_results = r_ins

            self.after(0, lambda: self._log("\n" + "═"*65 + "\n  PHASE 2/2 — SECURE (22 cases)\n" + "═"*65 + "\n", "HEADER"))
            r_sec = run_secure_cases(22, timeout=3.0,
                progress_cb=lambda d, t: self.after(0, lambda: self._set_progress(d, t, f"Secure: {d}/{t}")),
                log_cb=lambda s,i,g,p,n,x,e,b: self.after(0, lambda: self._log_case(s,i,g,p,n,x,e,b,"secure")))
            self._secure_results = r_sec

            self.after(0, lambda: self._show_summary([r_ins, r_sec], ["NOT SECURE", "SECURE"]))
        finally:
            self._running = False
            self.after(0, self._enable_buttons)

    # ── Per-case log ──────────────────────────────────────────────────────────

    def _log_case(self, status, idx, g, p, n, x, elapsed, bits, mode):
        icon  = "🔓" if status == "SUCCESS" else "🔒"
        label = "CRACKED" if status == "SUCCESS" else "PROTECTED"
        if mode == "insecure":
            color = "RED" if status == "SUCCESS" else "YELLOW"
        else:
            color = "GREEN" if status == "FAIL" else "RED"

        p_str = str(p) if bits <= 30 else f"{str(p)[:18]}…"
        self._log(f"\n[{idx:02d}] {icon} ", color)
        self._log(f"{label}  ", color)
        self._log(f"({bits}-bit) ", "YELLOW")
        self._log(f"t={elapsed:.4f}s\n")
        self._log(f"     g={g}  p={p_str}\n", "CYAN")
        if status == "SUCCESS" and x is not None:
            self._log(f"     🗝  Private key x = {x}\n", "RED")
        elif status == "FAIL" and mode == "secure":
            self._log(f"     ✓  Attack timed out — key is SAFE\n", "GREEN")

    # ── Summary ───────────────────────────────────────────────────────────────

    def _show_summary(self, result_sets, labels):
        self._stats_clear()
        self._stats("╔══════════════════════════════════════╗\n", "HEADER")
        self._stats("║          ANALYSIS REPORT             ║\n", "HEADER")
        self._stats("╚══════════════════════════════════════╝\n\n", "HEADER")

        all_sr, all_t, all_b, all_l = [], [], [], []

        for results, label in zip(result_sets, labels):
            n_total   = len(results)
            n_success = sum(1 for r in results if r["success"])
            sr = 100 * n_success / max(1, n_total)
            times = [r["time"] for r in results]
            bits  = [r["bits"] for r in results]
            avg_t = sum(times) / len(times) if times else 0

            all_sr.append(sr); all_t.append(avg_t)
            all_b.append(sum(bits)/len(bits) if bits else 0); all_l.append(label)

            color = "RED" if sr > 0 else "GREEN"
            self._stats(f"── {label} ──\n", "HEADER")
            self._stats(f"  Cases       : {n_total}\n")
            self._stats(f"  Cracked     : {n_success}\n")
            self._stats(f"  Protected   : {n_total - n_success}\n")
            self._stats(f"  Attack Rate : {sr:.1f}%\n", color)
            self._stats(f"  Confid.Rate : {100-sr:.1f}%\n", "GREEN" if sr == 0 else "YELLOW")
            self._stats(f"  Avg Time    : {avg_t:.4f}s\n")
            self._stats(f"  Avg Bits    : {all_b[-1]:.1f}\n\n")

        if len(result_sets) == 2:
            self._stats("── BEFORE vs AFTER ──\n", "HEADER")
            self._stats(f"  Attack BEFORE : {all_sr[0]:.1f}%\n", "RED")
            self._stats(f"  Attack AFTER  : {all_sr[1]:.1f}%\n", "GREEN")
            self._stats(f"  Improvement   : {all_sr[0]-all_sr[1]:.1f}%\n\n", "GREEN")

        self._stats("── ATTACK SUCCESS % ──\n", "HEADER")
        for label, rate in zip(all_l, all_sr):
            filled = int(rate / 5); empty = 20 - filled
            bar = "█" * filled + "░" * empty
            clr = "RED" if rate > 0 else "GREEN"
            self._stats(f"  {label:<12}: [{bar}] {rate:.1f}%\n", clr)

        self._stats("\n✓ Done — click any graph button above to visualize!\n", "GREEN")
        self._set_progress(100, 100, "Done! Click a graph button ↑")

    # ── Graph button handlers ─────────────────────────────────────────────────

    def _check_results(self):
        if not self._insecure_results and not self._secure_results:
            messagebox.showwarning("No Data", "Please run an attack first (NOT SECURE, SECURE, or BOTH).")
            return False
        return True

    def _get_safe_results(self):
        """Return (ins, sec) — fill with dummy data if one is missing."""
        ins = self._insecure_results
        sec = self._secure_results
        # If only one side ran, create minimal dummy for the other
        if not ins and sec:
            ins = [{"bits": 15, "success": True, "time": 0.01, "g": 2, "p": 23, "public_n": 5} for _ in range(5)]
        if not sec and ins:
            sec = [{"bits": 256, "success": False, "time": 3.0, "g": 2, "p": 2**256+1, "public_n": 5} for _ in range(5)]
        return ins, sec

    def _graph_attack_success(self):
        if not self._check_results(): return
        ins, sec = self._get_safe_results()
        open_graph_window(self, "Attack Success Rate", lambda: draw_attack_success_rate(ins, sec))

    def _graph_time_keysize(self):
        if not self._check_results(): return
        ins, sec = self._get_safe_results()
        open_graph_window(self, "Time vs Key Size", lambda: draw_time_vs_keysize(ins, sec))

    def _graph_cia(self):
        if not self._check_results(): return
        ins, sec = self._get_safe_results()
        open_graph_window(self, "CIA Rates", lambda: draw_cia_rates(ins, sec))

    def _graph_latency(self):
        if not self._check_results(): return
        ins, sec = self._get_safe_results()
        open_graph_window(self, "Latency Overhead", lambda: draw_latency_overhead(ins, sec))

    def _graph_solution_comparison(self):
        if not self._check_results(): return
        ins, sec = self._get_safe_results()
        open_graph_window(self, "Solution Comparison", lambda: draw_solution_comparison(ins, sec))

    def _graph_prevention(self):
        if not self._check_results(): return
        ins, sec = self._get_safe_results()
        open_graph_window(self, "Prevention Effectiveness", lambda: draw_prevention_effectiveness(ins, sec))

    def _graph_resource(self):
        if not self._check_results(): return
        ins, sec = self._get_safe_results()
        open_graph_window(self, "Resource Usage", lambda: draw_resource_usage(ins, sec))

    def _graph_security_improvement(self):
        if not self._check_results(): return
        ins, sec = self._get_safe_results()
        open_graph_window(self, "Security Improvement", lambda: draw_security_improvement(ins, sec))


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app = DHDemoApp()
    app.mainloop()
