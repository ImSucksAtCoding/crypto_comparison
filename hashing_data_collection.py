import hashlib
import hashlib
import os
import time
import pandas as pd
import psutil
import random
import platform
from tabulate import tabulate

# ============================================
# 🧠 Helper Functions
# ============================================

def get_memory_usage_mb():
    """Return current memory usage of process in MB."""
    process = psutil.Process(os.getpid())
    return process.memory_info().rss / (1024 * 1024)


def avalanche_effect(algo_func, data):
    """Calculates avalanche effect (% of bits changed)."""
    original_hash = algo_func(data).digest()
    flipped = bytearray(data)
    flipped[0] ^= 0b00000001
    flipped_hash = algo_func(flipped).digest()

    orig_bits = ''.join(format(b, '08b') for b in original_hash)
    flip_bits = ''.join(format(b, '08b') for b in flipped_hash)
    diff_bits = sum(a != b for a, b in zip(orig_bits, flip_bits))
    return (diff_bits / len(orig_bits)) * 100


def measure_cpu_usage(algo_func, data, iterations=10000):
    """Measure CPU utilization and total duration."""
    process = psutil.Process(os.getpid())
    start_cpu = process.cpu_percent(interval=None)
    start_time = time.perf_counter()

    for _ in range(iterations):
        algo_func(data).digest()

    duration = time.perf_counter() - start_time
    end_cpu = process.cpu_percent(interval=None)
    avg_cpu = (start_cpu + end_cpu) / 2
    return avg_cpu, duration


def init_overhead(algo_func, runs=1000):
    """Measure average initialization overhead."""
    times = []
    for _ in range(runs):
        t0 = time.perf_counter()
        _ = algo_func()
        times.append(time.perf_counter() - t0)
    return sum(times) / len(times)


# ============================================
# ⚙️ CPU Instruction Estimation (Windows)
# ============================================

def estimate_cpu_instructions(cpu_time_s, cpu_ghz=None, ipc=1.2):
    """Estimate CPU instructions = time × GHz × 1e9 × IPC."""
    try:
        if cpu_ghz is None:
            cpu_freq = psutil.cpu_freq()
            cpu_ghz = (cpu_freq.max or cpu_freq.current or 3000) / 1000.0
    except Exception:
        cpu_ghz = 3.0  # fallback default

    return int(cpu_time_s * cpu_ghz * 1e9 * ipc)


# ============================================
# 🚀 Benchmark Logic
# ============================================

def collect_hashing_data():
    print("\n🔍 Collecting Hashing Algorithm Data (Windows Compatible)\n")
    print("=" * 75)

    algorithms = {
        "MD5": hashlib.md5,
        "SHA1": hashlib.sha1,
        "SHA256": hashlib.sha256,
        "SHA3-256": hashlib.sha3_256,
        "BLAKE2b": hashlib.blake2b,
    }

    data_sizes = [64, 256, 1024, 4096]  # bytes
    iterations = 10000
    results = []

    for algo_name, algo_func in algorithms.items():
        print(f"\n⚙️  Testing {algo_name}...")
        init_time = init_overhead(algo_func, runs=500)

        for size in data_sizes:
            data = os.urandom(size)
            start_mem = get_memory_usage_mb()

            cpu_usage, duration = measure_cpu_usage(algo_func, data, iterations=iterations)
            throughput = size / (duration / iterations)
            cpu_instructions = estimate_cpu_instructions(duration)
            avalanche = avalanche_effect(algo_func, data)
            end_mem = get_memory_usage_mb()
            mem_used = max(end_mem - start_mem, 0)

            results.append({
                "Algorithm": algo_name,
                "InputBytes": size,
                "InitOverhead (s)": round(init_time, 8),
                "ExecTime (s)": round(duration, 6),
                "Throughput (B/s)": f"{throughput:,.0f}",
                "CPU Usage (%)": round(cpu_usage, 2),
                "Avalanche (%)": round(avalanche, 2),
                "MemUsed (MB)": round(mem_used, 4),
                "Est. CPU Instr.": f"{cpu_instructions:,}",
                "OutputBits": len(algo_func(data).hexdigest()) * 4
            })

            print(f"   ➜ Input {size} bytes | Time {duration:.6f}s | "
                  f"Instr ~{cpu_instructions/1e6:.2f}M | Avalanche {avalanche:.2f}%")

    # Convert to DataFrame
    df = pd.DataFrame(results)
    df_sorted = df.sort_values(by=["InputBytes", "Algorithm"], ascending=[True, True]).reset_index(drop=True)

    # Pretty table summary
    print("\n" + "=" * 75)
    print("📊 Benchmark Summary (sorted by Input Bytes):\n")
    print(tabulate(df_sorted, headers="keys", tablefmt="rounded_outline", showindex=False))

    # Save to CSV
    csv_name = "hashing_results_windows_sorted.csv"
    df_sorted.to_csv(csv_name, index=False)
    print(f"\n📁 Results saved to '{csv_name}'")

    return df_sorted


# ============================================
# 🧩 Entry Point
# ============================================
if __name__ == "__main__":
    if platform.system() != "Windows":
        print("⚠️  Warning: This script is tuned for Windows environments (no perf dependency).")
    collect_hashing_data()
