import os
import time
import math
import random
import psutil
import platform
import pandas as pd
from tabulate import tabulate
from Crypto.Cipher import AES, DES3, Blowfish, ChaCha20
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ===============================================================
# 🧠 Helper Functions
# ===============================================================

def get_memory_usage_mb():
    """Return memory usage of current process in MB."""
    process = psutil.Process(os.getpid())
    return process.memory_info().rss / (1024 * 1024)


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of data (0–8 bits per byte)."""
    if not data:
        return 0.0
    byte_counts = [0] * 256
    for b in data:
        byte_counts[b] += 1
    entropy = 0
    for count in byte_counts:
        if count == 0:
            continue
        p = count / len(data)
        entropy -= p * math.log2(p)
    return entropy


def measure_cpu_usage(func, *args, iterations=1000):
    """Measure average execution time and CPU utilization."""
    process = psutil.Process(os.getpid())
    start_cpu = process.cpu_percent(interval=None)
    start_time = time.perf_counter()

    for _ in range(iterations):
        func(*args)

    duration = time.perf_counter() - start_time
    end_cpu = process.cpu_percent(interval=None)
    avg_cpu = (start_cpu + end_cpu) / 2
    return avg_cpu, duration

# ===============================================================
# ⚙️ Cipher Bench Function
# ===============================================================

def encrypt_decrypt(cipher_ctor, key_size, data_size):
    """Run encryption/decryption test for a given cipher and key size."""
    key = get_random_bytes(key_size)
    data = os.urandom(data_size)
    iv = get_random_bytes(16)

    # Create cipher
    if cipher_ctor == AES:
        mode = AES.MODE_CBC
        cipher = AES.new(key, mode, iv)
    elif cipher_ctor == DES3:
        key = DES3.adjust_key_parity(get_random_bytes(24))
        mode = DES3.MODE_CBC
        cipher = DES3.new(key, mode, iv[:8])
    elif cipher_ctor == Blowfish:
        mode = Blowfish.MODE_CBC
        cipher = Blowfish.new(key, mode, iv[:8])
    elif cipher_ctor == AESGCM:
        cipher = AESGCM(key)
        mode = None
    elif cipher_ctor == ChaCha20:
        cipher = ChaCha20.new(key=key)
        mode = None
    else:
        raise ValueError("Unsupported cipher")

    # Measure key setup time
    start_key = time.perf_counter()
    _ = cipher
    key_setup_time = time.perf_counter() - start_key

    # Encryption
    start_enc = time.perf_counter()
    if cipher_ctor == AESGCM:
        nonce = get_random_bytes(12)
        ciphertext = cipher.encrypt(nonce, data, None)
    elif cipher_ctor == ChaCha20:
        ciphertext = cipher.encrypt(data)
    else:
        ciphertext = cipher.encrypt(pad(data, cipher.block_size))
    enc_time = time.perf_counter() - start_enc

    # Decryption
    start_dec = time.perf_counter()
    if cipher_ctor == AESGCM:
        _ = cipher.decrypt(nonce, ciphertext, None)
    elif cipher_ctor == ChaCha20:
        cipher2 = ChaCha20.new(key=key, nonce=cipher.nonce)
        _ = cipher2.decrypt(ciphertext)
    else:
        cipher2 = cipher_ctor.new(key, mode, iv[:8] if cipher_ctor in [DES3, Blowfish] else iv)
        _ = unpad(cipher2.decrypt(ciphertext), cipher.block_size)
    dec_time = time.perf_counter() - start_dec

    # Ciphertext entropy
    entropy = calculate_entropy(ciphertext)
    return enc_time, dec_time, key_setup_time, entropy

# ===============================================================
# 🚀 Main Benchmark
# ===============================================================

def collect_encryption_data():
    print("\n🔐 Collecting Symmetric Encryption Algorithm Data...\n")
    print("=" * 80)

    algorithms = {
        "AES-128": (AES, 16),
        "AES-256": (AES, 32),
        "3DES": (DES3, 24),
        "Blowfish": (Blowfish, 16),
        "AES-GCM": (AESGCM, 32),
        "ChaCha20": (ChaCha20, 32),
    }

    data_sizes = [64, 256, 1024, 4096]
    results = []

    for algo_name, (cipher_ctor, key_size) in algorithms.items():
        print(f"\n⚙️  Testing {algo_name}...")
        for size in data_sizes:
            start_mem = get_memory_usage_mb()

            enc_time, dec_time, key_time, entropy = encrypt_decrypt(cipher_ctor, key_size, size)
            avg_time = (enc_time + dec_time) / 2
            throughput = size / avg_time if avg_time > 0 else 0

            end_mem = get_memory_usage_mb()
            mem_used = max(end_mem - start_mem, 0)

            results.append({
                "Algorithm": algo_name,
                "InputBytes": size,
                "KeySetup (s)": round(key_time, 8),
                "EncryptTime (s)": round(enc_time, 6),
                "DecryptTime (s)": round(dec_time, 6),
                "Throughput (B/s)": f"{throughput:,.0f}",
                "Entropy (bits)": round(entropy, 3),
                "MemoryUsage (MB)": round(mem_used, 4)
            })

            print(f"   ➜ {algo_name:<9} | {size:>6} bytes | Enc {enc_time:.6f}s | "
                  f"Dec {dec_time:.6f}s | Entropy {entropy:.2f}")

    # Convert to DataFrame
    df = pd.DataFrame(results)
    df_sorted = df.sort_values(by=["InputBytes", "Algorithm"]).reset_index(drop=True)

    # Pretty summary
    print("\n" + "=" * 80)
    print("📊 Symmetric Encryption Benchmark Summary (sorted by Input Bytes):\n")
    print(tabulate(df_sorted, headers="keys", tablefmt="rounded_outline", showindex=False))

    csv_name = "symmetric_encryption_results.csv"
    df_sorted.to_csv(csv_name, index=False)
    print(f"\n📁 Results saved to '{csv_name}'")
    return df_sorted


# ===============================================================
# 🧩 Entry Point
# ===============================================================
if __name__ == "__main__":
    if platform.system() != "Windows":
        print("⚠️  Note: This script is optimized for Windows or generic environments.")
    collect_encryption_data()
