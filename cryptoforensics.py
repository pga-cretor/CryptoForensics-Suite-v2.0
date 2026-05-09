#!/usr/bin/env python3

import sys
import os
import math
import hashlib
import argparse
import struct
import string
import time
import itertools
from pathlib import Path
from collections import Counter
from typing import Any, List, Optional


Image: Any = None
try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

# Pre-declare Rich names so Pylance doesn't flag them as "possibly unbound"
# when they are only used inside `if RICH_AVAILABLE:` guards.
Table: Any = None
Panel: Any = None
Progress: Any = None
BarColumn: Any = None
TextColumn: Any = None
TimeElapsedColumn: Any = None
Text: Any = None
Columns: Any = None
box: Any = None
console: Any = None

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn
    from rich.text import Text
    from rich.columns import Columns
    from rich import box
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    class Console:  # type: ignore[no-redef]
        def print(self, *a: Any, **k: Any) -> None: print(*[str(x) for x in a])
        def rule(self, *a: Any, **k: Any) -> None: print("─" * 60)
    console = Console()

# ══════════════════════════════════════════════════════════════
#  BANNER
# ══════════════════════════════════════════════════════════════

BANNER = r"""
[cyan]
  ██████╗██████╗ ██╗   ██╗██████╗ ████████╗ ██████╗ 
 ██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝██╔═══██╗
 ██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   ██║   ██║
 ██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   ██║   ██║
 ╚██████╗██║  ██║   ██║   ██║        ██║   ╚██████╔╝
  ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝    ╚═════╝ [/cyan]
[bright_black] ███████╗ ██████╗ ██████╗ ███████╗███╗   ██╗███████╗██╗ ██████╗███████╗
 ██╔════╝██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔════╝██║██╔════╝██╔════╝
 █████╗  ██║   ██║██████╔╝█████╗  ██╔██╗ ██║███████╗██║██║     ███████╗
 ██╔══╝  ██║   ██║██╔══██╗██╔══╝  ██║╚██╗██║╚════██║██║██║     ╚════██║
 ██║     ╚██████╔╝██║  ██║███████╗██║ ╚████║███████║██║╚██████╗███████║
 ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝ ╚═════╝╚══════╝[/bright_black]

[bold white]         ╔══════════════════════════════════════════╗
         ║  v2.0  ·  Ethical Hacking & Forensics    ║
         ║  Hash · Steganography · Entropy Analysis  ║
         ╚══════════════════════════════════════════╝[/bold white]
"""

BANNER_PLAIN = """
  ╔══════════════════════════════════════════════════╗
  ║       CRYPTOFORENSICS SUITE v2.0                 ║
  ║   Hash · Steganography · Entropy Analysis        ║
  ║   Advanced Cryptography & Digital Forensics      ║
  ╚══════════════════════════════════════════════════╝
"""

# ══════════════════════════════════════════════════════════════
#  MODULE 1: HASH ANALYZER
# ══════════════════════════════════════════════════════════════

HASH_SIGNATURES = {
    32:  [("MD5",         "high",  "RFC 1321 — Legacy, collision-prone"),
          ("NTLM",        "medium","Windows password hash"),
          ("MD4",         "low",   "Obsolete, rarely used"),
          ("LM",          "low",   "Legacy Windows LAN Manager")],
    40:  [("SHA-1",       "high",  "RFC 3174 — Deprecated since 2017"),
          ("MySQL 3.x",   "medium","Old MySQL password hash"),
          ("RIPEMD-160",  "low",   "RACE Integrity Primitives")],
    48:  [("SHA-224",     "high",  "SHA-2 family, 224-bit"),
          ("Haval-192",   "low",   "Variable-length hash")],
    56:  [("SHA-224",     "high",  "SHA-2 family, 224-bit"),
          ("Haval-224",   "low",   "Variable-length hash")],
    64:  [("SHA-256",     "high",  "SHA-2 family — Current standard"),
          ("BLAKE2s",     "medium","High-speed modern hash"),
          ("Keccak-256",  "medium","Ethereum/Solidity default"),
          ("Whirlpool",   "low",   "Nessie submission")],
    96:  [("SHA-384",     "high",  "SHA-2 family, 384-bit")],
    128: [("SHA-512",     "high",  "SHA-2 family — Strong security"),
          ("BLAKE2b",     "medium","High-speed modern hash"),
          ("Whirlpool",   "low",   "512-bit, NESSIE project")],
}

ALGO_MAP = {
    "md5":     hashlib.md5,
    "sha1":    hashlib.sha1,
    "sha224":  hashlib.sha224,
    "sha256":  hashlib.sha256,
    "sha384":  hashlib.sha384,
    "sha512":  hashlib.sha512,
    "sha3_256":hashlib.sha3_256,
    "sha3_512":hashlib.sha3_512,
    "blake2b": lambda: hashlib.blake2b(digest_size=64),
    "blake2s": lambda: hashlib.blake2s(digest_size=32),
}

def identify_hash(hash_str: str) -> list:
    """Identify hash type based on length and character set."""
    h = hash_str.strip().lower()
    results = []

    if not h:
        return [{"type": "Empty", "confidence": "none", "note": "No input provided"}]

    # Check special prefixes
    if h.startswith("$2"):
        return [{"type": "bcrypt", "confidence": "high", "note": "Cost factor embedded in hash", "bits": "N/A"}]
    if h.startswith("$1$"):
        return [{"type": "MD5-crypt", "confidence": "high", "note": "Linux /etc/shadow format", "bits": "128"}]
    if h.startswith("$6$"):
        return [{"type": "SHA-512-crypt", "confidence": "high", "note": "Modern Linux /etc/shadow", "bits": "512"}]
    if h.startswith("$5$"):
        return [{"type": "SHA-256-crypt", "confidence": "high", "note": "Linux /etc/shadow format", "bits": "256"}]

    is_hex = all(c in string.hexdigits for c in h)
    is_b64 = all(c in string.ascii_letters + string.digits + "+/=" for c in h)

    if not is_hex and not is_b64:
        return [{"type": "Unknown", "confidence": "low", "note": "Non-hex/non-b64 characters detected"}]

    length = len(h)
    if length in HASH_SIGNATURES:
        for htype, conf, note in HASH_SIGNATURES[length]:
            results.append({"type": htype, "confidence": conf, "note": note, "bits": length * 4})
    else:
        results.append({
            "type": "Unknown",
            "confidence": "low",
            "note": f"Unusual length ({length} chars = {length*4} bits)"
        })

    return results

def compute_hashes(data: str) -> dict:
    """Compute all supported hashes for input string."""
    results = {}
    encoded = data.encode("utf-8")
    for name, algo_fn in ALGO_MAP.items():
        try:
            h = algo_fn()
            h.update(encoded)
            results[name] = h.hexdigest()
        except Exception as e:
            results[name] = f"ERROR: {e}"
    return results

def compute_file_hashes(filepath: str) -> dict:
    """Compute hashes for a file."""
    results = {}
    hashers = {name: algo_fn() for name, algo_fn in ALGO_MAP.items()}
    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(65536):
                for h in hashers.values():
                    h.update(chunk)
        for name, h in hashers.items():
            results[name] = h.hexdigest()
    except Exception as e:
        return {"error": str(e)}
    return results

def crack_hash(target_hash: str, wordlist_path: Optional[str] = None,
               words: Optional[List[str]] = None, algo: str = "auto") -> dict:
    """
    Crack a hash using dictionary attack.
    Returns dict with found/not_found status and stats.
    """
    target = target_hash.strip().lower()

    # Auto-detect algorithm
    if algo == "auto":
        ids = identify_hash(target)
        detected = ids[0]["type"] if ids else "MD5"
        algo_name = detected.split("-")[0].lower().replace(" ", "")
        if algo_name not in ALGO_MAP:
            algo_name = "md5"
    else:
        algo_name = algo.lower().replace("-", "").replace("_", "")
        if algo_name not in ALGO_MAP:
            algo_name = "md5"

    # Load wordlist
    if wordlist_path:
        try:
            with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                words = [line.strip() for line in f if line.strip()]
        except Exception as e:
            return {"status": "error", "message": str(e)}

    if not words:
        return {"status": "error", "message": "No wordlist provided"}

    word_list: List[str] = words
    start = time.time()
    checked = 0

    if RICH_AVAILABLE:
        with Progress(
            TextColumn("[cyan]  Cracking:[/cyan]"),
            BarColumn(bar_width=30),
            TextColumn("{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task("cracking", total=len(word_list))
            for word in word_list:
                try:
                    h = ALGO_MAP[algo_name]()
                    h.update(word.encode("utf-8", errors="ignore"))
                    digest = h.hexdigest()
                except:
                    checked += 1
                    progress.advance(task)
                    continue

                checked += 1
                progress.advance(task)

                if digest == target:
                    elapsed = time.time() - start
                    return {
                        "status": "found",
                        "plaintext": word,
                        "algorithm": algo_name.upper(),
                        "checked": checked,
                        "total": len(word_list),
                        "elapsed": round(elapsed, 3),
                        "speed": round(checked / elapsed) if elapsed > 0 else 0,
                    }
    else:
        for word in word_list:
            try:
                h = ALGO_MAP[algo_name]()
                h.update(word.encode("utf-8", errors="ignore"))
                if h.hexdigest() == target:
                    return {
                        "status": "found",
                        "plaintext": word,
                        "algorithm": algo_name.upper(),
                        "checked": checked,
                        "elapsed": round(time.time() - start, 3),
                    }
            except:
                pass
            checked += 1

    elapsed = time.time() - start
    return {
        "status": "not_found",
        "algorithm": algo_name.upper(),
        "checked": checked,
        "total": len(word_list),
        "elapsed": round(elapsed, 3),
        "speed": round(checked / elapsed) if elapsed > 0 else 0,
    }

# ══════════════════════════════════════════════════════════════
#  MODULE 2: STEGANOGRAPHY DETECTOR (LSB Analysis)
# ══════════════════════════════════════════════════════════════

def lsb_analysis(image_path: str) -> dict:
    """
    Perform full LSB steganography analysis on an image.
    Returns detailed stats per channel and a suspicion score.
    """
    if not PIL_AVAILABLE:
        return {"error": "Pillow not installed. Run: pip install Pillow"}

    try:
        img = Image.open(image_path).convert("RGB")
    except Exception as e:
        return {"error": f"Cannot open image: {e}"}

    width, height = img.size
    pixels = list(img.getdata())
    total_pixels = len(pixels)

    channels = {"R": [], "G": [], "B": []}
    for r, g, b in pixels:
        channels["R"].append(r)
        channels["G"].append(g)
        channels["B"].append(b)

    results = {
        "file": image_path,
        "dimensions": f"{width}x{height}",
        "total_pixels": total_pixels,
        "channels": {},
        "lsb_bits": [],
        "suspicion_score": 0,
        "verdict": "",
    }

    suspicion = 0

    for ch_name, values in channels.items():
        lsb_vals = [v & 1 for v in values]
        lsb_ones = sum(lsb_vals)
        lsb_zeros = len(lsb_vals) - lsb_ones
        ratio = lsb_ones / len(lsb_vals) if lsb_vals else 0

        # Chi-squared test for LSB uniformity (indicator of steganography)
        expected = total_pixels / 2
        if expected > 0:
            chi2 = ((lsb_ones - expected) ** 2 + (lsb_zeros - expected) ** 2) / expected
        else:
            chi2 = 0

        # Bit pair analysis — adjacent LSB pairs
        pairs = Counter(zip(lsb_vals[::2], lsb_vals[1::2]))
        pair_entropy = shannon_entropy(list(pairs.values()))

        # Suspicion heuristics
        ch_suspicion = 0
        if 0.48 <= ratio <= 0.52:    # Very uniform → likely stego
            ch_suspicion += 3
        if chi2 < 1.0:               # Very low chi2 → suspicious uniformity
            ch_suspicion += 2
        if pair_entropy > 1.95:      # Near-max pair entropy
            ch_suspicion += 2

        suspicion += ch_suspicion

        results["channels"][ch_name] = {
            "lsb_ones": lsb_ones,
            "lsb_zeros": lsb_zeros,
            "ratio": round(ratio, 4),
            "chi2": round(chi2, 4),
            "pair_entropy": round(pair_entropy, 4),
            "suspicion": ch_suspicion,
        }

    # Extract LSB stream
    all_lsb = []
    for r, g, b in pixels[:1024]:  # First 1024 pixels
        all_lsb.append(r & 1)
        all_lsb.append(g & 1)
        all_lsb.append(b & 1)
    results["lsb_bits"] = all_lsb

    # Try ASCII decode
    results["decoded_text"] = try_decode_lsb(all_lsb)

    # Capacity calculation
    capacity_bytes = (total_pixels * 3) // 8
    results["capacity_bytes"] = capacity_bytes
    results["capacity_kb"] = round(capacity_bytes / 1024, 2)

    # Verdict
    results["suspicion_score"] = suspicion
    if suspicion >= 9:
        results["verdict"] = "HIGH — Strong indicators of steganographic content"
        results["verdict_level"] = "danger"
    elif suspicion >= 5:
        results["verdict"] = "MEDIUM — Possible hidden data, further analysis recommended"
        results["verdict_level"] = "warn"
    elif suspicion >= 2:
        results["verdict"] = "LOW — Minor anomalies, likely clean"
        results["verdict_level"] = "info"
    else:
        results["verdict"] = "CLEAN — No significant steganographic indicators"
        results["verdict_level"] = "ok"

    return results

def try_decode_lsb(bits: list) -> str:
    """Attempt to decode LSB stream as ASCII text."""
    if len(bits) < 8:
        return ""
    text = ""
    for i in range(0, min(len(bits) - 7, 256 * 8), 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        if 32 <= byte <= 126:
            text += chr(byte)
        elif byte == 0 and len(text) > 3:
            break
        else:
            text += "."
    printable = "".join(c for c in text if c in string.printable)
    return printable if len(printable) > 4 else ""

def save_lsb_visualization(image_path: str, output_path: Optional[str] = None) -> str:
    """Save LSB-amplified visualization image."""
    if not PIL_AVAILABLE:
        return "Pillow not available"
    try:
        img = Image.open(image_path).convert("RGB")
        pixels = img.load()
        assert pixels is not None, "Failed to load image pixel data"
        w, h = img.size
        new_img = Image.new("RGB", (w, h))
        new_pixels = new_img.load()
        assert new_pixels is not None, "Failed to load new image pixel data"
        for y in range(h):
            for x in range(w):
                r, g, b = pixels[x, y]
                new_pixels[x, y] = ((r & 1) * 255, (g & 1) * 255, (b & 1) * 255)
        if not output_path:
            stem = Path(image_path).stem
            output_path = str(Path(image_path).parent / f"{stem}_lsb_vis.png")
        new_img.save(output_path)
        return output_path
    except Exception as e:
        return f"Error: {e}"

# ══════════════════════════════════════════════════════════════
#  MODULE 3: ENTROPY ANALYZER
# ══════════════════════════════════════════════════════════════

def shannon_entropy(data) -> float:
    """Calculate Shannon entropy (bits per symbol)."""
    if not data:
        return 0.0
    if isinstance(data, (str, bytes)):
        counter = Counter(data if isinstance(data, bytes) else data.encode("utf-8", errors="ignore"))
        total = len(data)
    else:
        counter = Counter(data)
        total = sum(counter.values())
    if total == 0:
        return 0.0
    entropy = 0.0
    for count in counter.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy

def analyze_entropy(data: bytes, label: str = "data") -> dict:
    """
    Full entropy analysis of binary data.
    Returns entropy, byte distribution, verdict.
    """
    if not data:
        return {"error": "No data provided"}

    size = len(data)
    counter = Counter(data)
    entropy = shannon_entropy(data)

    # Byte frequency distribution
    freq = {i: counter.get(i, 0) for i in range(256)}
    top_bytes = sorted(freq.items(), key=lambda x: -x[1])[:16]

    # Chi-squared test for randomness
    expected = size / 256
    chi2 = sum((freq[i] - expected) ** 2 / expected for i in range(256)) if expected > 0 else 0

    # Unique bytes ratio
    unique_bytes = len(counter)
    unique_ratio = unique_bytes / 256

    # Printable ratio
    printable_count = sum(1 for b in data if 32 <= b <= 126)
    printable_ratio = printable_count / size

    # Block-level entropy (64-byte blocks)
    block_size = 64
    block_entropies = []
    for i in range(0, min(size, 4096), block_size):
        block = data[i:i + block_size]
        if len(block) >= 8:
            block_entropies.append(round(shannon_entropy(block), 3))

    avg_block_entropy = sum(block_entropies) / len(block_entropies) if block_entropies else 0
    min_block_entropy = min(block_entropies) if block_entropies else 0
    max_block_entropy = max(block_entropies) if block_entropies else 0

    # Verdict
    verdict, verdict_level = classify_entropy(entropy, printable_ratio, unique_ratio, chi2)

    return {
        "label": label,
        "size_bytes": size,
        "size_kb": round(size / 1024, 2),
        "entropy": round(entropy, 6),
        "entropy_pct": round((entropy / 8.0) * 100, 1),
        "unique_bytes": unique_bytes,
        "unique_ratio": round(unique_ratio, 3),
        "printable_ratio": round(printable_ratio, 3),
        "chi2": round(chi2, 2),
        "top_bytes": top_bytes,
        "block_entropies": block_entropies[:32],
        "avg_block_entropy": round(avg_block_entropy, 3),
        "min_block_entropy": round(min_block_entropy, 3),
        "max_block_entropy": round(max_block_entropy, 3),
        "verdict": verdict,
        "verdict_level": verdict_level,
    }

def classify_entropy(entropy: float, printable_ratio: float,
                     unique_ratio: float, chi2: float) -> tuple:
    """Classify data type based on entropy and other metrics."""
    if entropy >= 7.5 and unique_ratio > 0.95:
        return ("ENCRYPTED / RANDOM — High entropy, near-uniform byte distribution. "
                "Consistent with AES/ChaCha20 ciphertext or compressed data.", "danger")
    elif entropy >= 7.0 and unique_ratio > 0.85:
        return ("COMPRESSED / PACKED — Very high entropy. Possible zip/gzip/UPX-packed executable "
                "or encrypted archive.", "warn")
    elif entropy >= 6.0:
        return ("BINARY / MIXED — Elevated entropy. May contain encoded data, "
                "compiled binary, or mixed content.", "info")
    elif entropy >= 4.0 and printable_ratio > 0.7:
        return ("NATURAL LANGUAGE TEXT — Moderate entropy. Typical for English text, "
                "source code, or config files.", "ok")
    elif entropy < 2.0:
        return ("LOW COMPLEXITY — Very low entropy. Highly repetitive data, "
                "padding, or null bytes.", "ok")
    else:
        return ("STRUCTURED DATA — Moderate-low entropy. Possible CSV, JSON, "
                "XML, or formatted binary.", "ok")

def analyze_entropy_file(filepath: str) -> dict:
    """Analyze entropy of a file."""
    try:
        path = Path(filepath)
        with open(path, "rb") as f:
            data = f.read()
        result = analyze_entropy(data, label=path.name)
        result["filepath"] = str(path.resolve())
        result["extension"] = path.suffix.lower()
        return result
    except Exception as e:
        return {"error": str(e)}

# ══════════════════════════════════════════════════════════════
#  DISPLAY FUNCTIONS (Rich)
# ══════════════════════════════════════════════════════════════

def print_banner():
    if RICH_AVAILABLE:
        console.print(BANNER)
    else:
        print(BANNER_PLAIN)

def conf_color(c):
    return {"high": "green", "medium": "yellow", "low": "red"}.get(c, "white")

def verdict_color(level):
    return {"danger": "bold red", "warn": "bold yellow",
            "info": "bold cyan", "ok": "bold green"}.get(level, "white")

def display_hash_identify(hash_str: str):
    ids = identify_hash(hash_str)
    if RICH_AVAILABLE:
        console.rule("[cyan]HASH IDENTIFICATION[/cyan]")
        console.print(f"\n[dim]Input:[/dim] [bold white]{hash_str}[/bold white]")
        console.print(f"[dim]Length:[/dim] [yellow]{len(hash_str.strip())} chars "
                      f"({len(hash_str.strip()) * 4} bits)[/yellow]\n")
        t = Table(box=box.SIMPLE_HEAD, header_style="bold cyan")
        t.add_column("Algorithm", style="bold white")
        t.add_column("Confidence", justify="center")
        t.add_column("Bits", justify="right", style="yellow")
        t.add_column("Notes", style="dim")
        for r in ids:
            t.add_row(
                r.get("type", "?"),
                f"[{conf_color(r.get('confidence','low'))}]{r.get('confidence','?').upper()}[/]",
                str(r.get("bits", "N/A")),
                r.get("note", ""),
            )
        console.print(t)
    else:
        print("\n── HASH IDENTIFICATION ──")
        print(f"Input : {hash_str}")
        print(f"Length: {len(hash_str.strip())} chars")
        for r in ids:
            print(f"  [{r['confidence'].upper()}] {r['type']}  — {r.get('note','')}")

def display_hashes(hashes: dict):
    if RICH_AVAILABLE:
        console.rule("[cyan]COMPUTED HASHES[/cyan]")
        t = Table(box=box.SIMPLE_HEAD, header_style="bold cyan")
        t.add_column("Algorithm", style="bold white", min_width=12)
        t.add_column("Digest", style="green")
        for name, digest in hashes.items():
            t.add_row(name.upper(), digest)
        console.print(t)
    else:
        print("\n── COMPUTED HASHES ──")
        for name, digest in hashes.items():
            print(f"  {name.upper():12s}  {digest}")

def display_crack_result(result: dict):
    if RICH_AVAILABLE:
        console.rule("[cyan]CRACK RESULT[/cyan]")
        if result.get("status") == "found":
            console.print(Panel(
                f"[bold green]✓ CRACKED[/bold green]\n\n"
                f"  Plaintext  : [bold white]{result['plaintext']}[/bold white]\n"
                f"  Algorithm  : [cyan]{result.get('algorithm','?')}[/cyan]\n"
                f"  Words tried: [yellow]{result.get('checked',0):,}[/yellow] / {result.get('total',0):,}\n"
                f"  Time       : [yellow]{result.get('elapsed',0)}s[/yellow]\n"
                f"  Speed      : [yellow]{result.get('speed',0):,} h/s[/yellow]",
                border_style="green", title="[green]SUCCESS[/green]"
            ))
        elif result.get("status") == "not_found":
            console.print(Panel(
                f"[bold red]✗ NOT FOUND[/bold red]\n\n"
                f"  Algorithm  : [cyan]{result.get('algorithm','?')}[/cyan]\n"
                f"  Words tried: [yellow]{result.get('checked',0):,}[/yellow]\n"
                f"  Time       : [yellow]{result.get('elapsed',0)}s[/yellow]\n"
                f"  Speed      : [yellow]{result.get('speed',0):,} h/s[/yellow]\n\n"
                f"  [dim]Try a larger wordlist (e.g. rockyou.txt)[/dim]",
                border_style="red", title="[red]FAILED[/red]"
            ))
        else:
            console.print(f"[red]Error:[/red] {result.get('message', 'Unknown error')}")
    else:
        print("\n── CRACK RESULT ──")
        if result.get("status") == "found":
            print(f"  [CRACKED] Plaintext: {result['plaintext']}")
        else:
            print(f"  [NOT FOUND] {result.get('checked',0)} words tested")

def display_stego_result(result: dict):
    if "error" in result:
        console.print(f"[red]Error:[/red] {result['error']}")
        return

    if RICH_AVAILABLE:
        console.rule("[cyan]LSB STEGANOGRAPHY ANALYSIS[/cyan]")
        console.print(f"\n[dim]File:[/dim]       [white]{result['file']}[/white]")
        console.print(f"[dim]Dimensions:[/dim] [yellow]{result['dimensions']}[/yellow]  "
                      f"[dim]Pixels:[/dim] [yellow]{result['total_pixels']:,}[/yellow]")
        console.print(f"[dim]LSB Capacity:[/dim] [yellow]{result['capacity_kb']} KB "
                      f"({result['capacity_bytes']:,} bytes)[/yellow]\n")

        t = Table(box=box.SIMPLE_HEAD, header_style="bold cyan", title="Channel Analysis")
        t.add_column("Channel", style="bold white")
        t.add_column("LSB-1s", justify="right")
        t.add_column("LSB-0s", justify="right")
        t.add_column("Ratio", justify="right")
        t.add_column("Chi²", justify="right")
        t.add_column("Pair Entropy", justify="right")
        t.add_column("Suspicion", justify="center")

        colors = {"R": "red", "G": "green", "B": "blue"}
        for ch, data in result["channels"].items():
            susp = data["suspicion"]
            susp_str = ("🔴 HIGH" if susp >= 6 else "🟡 MED" if susp >= 3 else "🟢 LOW")
            t.add_row(
                f"[bold {colors[ch]}]{ch}[/bold {colors[ch]}]",
                str(data["lsb_ones"]),
                str(data["lsb_zeros"]),
                f"{data['ratio']:.4f}",
                f"{data['chi2']:.4f}",
                f"{data['pair_entropy']:.4f}",
                susp_str,
            )
        console.print(t)

        # LSB bit sample
        bits_preview = "".join(str(b) for b in result["lsb_bits"][:128])
        console.print(f"\n[dim]LSB stream (first 128 bits):[/dim]")
        console.print(f"[green]{bits_preview[:64]}[/green]")
        console.print(f"[green]{bits_preview[64:]}[/green]")

        if result.get("decoded_text"):
            console.print(f"\n[dim]ASCII decode attempt:[/dim] [bold yellow]{result['decoded_text']}[/bold yellow]")

        # Verdict
        lvl = result.get("verdict_level", "info")
        console.print(Panel(
            f"[{verdict_color(lvl)}]Suspicion Score: {result['suspicion_score']}/21[/{verdict_color(lvl)}]\n\n"
            f"{result['verdict']}",
            border_style=verdict_color(lvl),
            title=f"[{verdict_color(lvl)}]VERDICT[/{verdict_color(lvl)}]"
        ))
    else:
        print("\n── LSB STEGANOGRAPHY ANALYSIS ──")
        print(f"  File: {result['file']}")
        print(f"  Dimensions: {result['dimensions']}")
        print(f"  Suspicion Score: {result['suspicion_score']}/21")
        print(f"  Verdict: {result['verdict']}")
        for ch, data in result["channels"].items():
            print(f"  Channel {ch}: ratio={data['ratio']:.4f} chi2={data['chi2']:.4f}")

def display_entropy_result(result: dict):
    if "error" in result:
        console.print(f"[red]Error:[/red] {result['error']}")
        return

    if RICH_AVAILABLE:
        console.rule("[cyan]ENTROPY ANALYSIS[/cyan]")
        console.print(f"\n[dim]Source:[/dim] [white]{result['label']}[/white]  "
                      f"[dim]Size:[/dim] [yellow]{result['size_bytes']:,} bytes "
                      f"({result['size_kb']} KB)[/yellow]\n")

        # Entropy bar
        pct = result["entropy_pct"]
        bar_len = 50
        filled = int(bar_len * pct / 100)
        if pct >= 90:
            bar_color = "red"
        elif pct >= 75:
            bar_color = "yellow"
        elif pct >= 40:
            bar_color = "cyan"
        else:
            bar_color = "green"

        bar = "█" * filled + "░" * (bar_len - filled)
        console.print(f"[bold]Shannon Entropy:[/bold]")
        console.print(f"  [{bar_color}]{bar}[/{bar_color}]  "
                      f"[bold {bar_color}]{result['entropy']:.4f} bits/byte[/bold {bar_color}]  "
                      f"([{bar_color}]{pct}%[/{bar_color}])\n")

        # Stats table
        t = Table(box=box.SIMPLE_HEAD, header_style="bold cyan")
        t.add_column("Metric", style="dim")
        t.add_column("Value", style="bold white")
        t.add_column("Interpretation", style="dim")
        t.add_row("Entropy",         f"{result['entropy']:.6f} bits/byte",  "Max = 8.0 (perfect random)")
        t.add_row("Unique bytes",    f"{result['unique_bytes']}/256",         f"{result['unique_ratio']*100:.1f}% of byte space used")
        t.add_row("Printable chars", f"{result['printable_ratio']*100:.1f}%", ">70% = likely text")
        t.add_row("Chi² statistic",  f"{result['chi2']:.2f}",                "<50 = uniform (encrypted/random)")
        min_be = result['min_block_entropy']
        max_be = result['max_block_entropy']
        t.add_row("Block entropy",   f"{result['avg_block_entropy']:.3f} avg", f"Min:{min_be} Max:{max_be}")
        console.print(t)

        # Top bytes
        if result["top_bytes"]:
            console.print("\n[dim]Top 8 most frequent bytes:[/dim]")
            for byte_val, count in result["top_bytes"][:8]:
                bar_w = int(20 * count / result["size_bytes"]) + 1
                console.print(f"  [cyan]0x{byte_val:02X}[/cyan] ({byte_val:3d}) "
                               f"[green]{'▌'*bar_w}[/green] {count:,}")

        # Block entropy sparkline
        if result["block_entropies"]:
            console.print(f"\n[dim]Block entropy profile ({len(result['block_entropies'])} blocks of 64 bytes):[/dim]")
            spark = ""
            chars = " ▁▂▃▄▅▆▇█"
            for e in result["block_entropies"]:
                idx = min(int(e / 8.0 * 8), 8)
                spark += chars[idx]
            console.print(f"  [green]{spark}[/green]  (▁=low → █=high)")

        # Verdict
        lvl = result.get("verdict_level", "info")
        console.print(Panel(
            f"{result['verdict']}",
            border_style=verdict_color(lvl),
            title=f"[{verdict_color(lvl)}]CLASSIFICATION[/{verdict_color(lvl)}]"
        ))
    else:
        print("\n── ENTROPY ANALYSIS ──")
        print(f"  Source  : {result['label']}")
        print(f"  Entropy : {result['entropy']:.4f} bits/byte ({result['entropy_pct']}%)")
        print(f"  Verdict : {result['verdict']}")

# ══════════════════════════════════════════════════════════════
#  CLI INTERFACE
# ══════════════════════════════════════════════════════════════

def build_parser():
    parser = argparse.ArgumentParser(
        prog="cryptoforensics",
        description="CryptoForensics Suite — Hash · Steganography · Entropy",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  # Hash identification
  cryptoforensics hash identify 5f4dcc3b5aa765d61d8327deb882cf99

  # Generate all hashes for a string
  cryptoforensics hash generate "password123"

  # Hash a file
  cryptoforensics hash file /path/to/file.bin

  # Crack a hash with a wordlist
  cryptoforensics hash crack 5f4dcc3b5aa765d61d8327deb882cf99 --wordlist rockyou.txt

  # Crack with inline words
  cryptoforensics hash crack <hash> --words password admin 123456

  # LSB steganography analysis
  cryptoforensics stego analyze image.png

  # Save LSB visualization
  cryptoforensics stego analyze image.png --save-vis

  # Entropy analysis of a string
  cryptoforensics entropy string "Hello, World!"

  # Entropy analysis of a file
  cryptoforensics entropy file /path/to/suspicious.bin

  # Entropy of hex data
  cryptoforensics entropy string "aabbccdd..." --hex
        """
    )

    sub = parser.add_subparsers(dest="module", required=True)

    # ── HASH ──
    hash_p = sub.add_parser("hash", help="Hash analysis, generation, and cracking")
    hash_sub = hash_p.add_subparsers(dest="action", required=True)

    h_id = hash_sub.add_parser("identify", help="Identify hash type")
    h_id.add_argument("hash", help="Hash string to identify")

    h_gen = hash_sub.add_parser("generate", help="Generate hashes for input string")
    h_gen.add_argument("text", help="Plaintext to hash")

    h_file = hash_sub.add_parser("file", help="Hash all algorithms on a file")
    h_file.add_argument("filepath", help="File to hash")

    h_crack = hash_sub.add_parser("crack", help="Dictionary attack on hash")
    h_crack.add_argument("hash", help="Hash to crack")
    h_crack.add_argument("--wordlist", "-w", help="Path to wordlist file")
    h_crack.add_argument("--words", "-W", nargs="+", help="Inline word list")
    h_crack.add_argument("--algo", "-a", default="auto",
                         choices=["auto","md5","sha1","sha224","sha256","sha384","sha512","sha3_256","sha3_512"],
                         help="Algorithm (default: auto-detect)")

    # ── STEGO ──
    stego_p = sub.add_parser("stego", help="Steganography detection and LSB analysis")
    stego_sub = stego_p.add_subparsers(dest="action", required=True)

    s_analyze = stego_sub.add_parser("analyze", help="LSB analysis of image")
    s_analyze.add_argument("image", help="Image file (PNG/BMP/JPG)")
    s_analyze.add_argument("--save-vis", action="store_true", help="Save LSB visualization image")
    s_analyze.add_argument("--output", "-o", help="Output path for visualization")

    # ── ENTROPY ──
    ent_p = sub.add_parser("entropy", help="Entropy analysis and file classification")
    ent_sub = ent_p.add_subparsers(dest="action", required=True)

    e_str = ent_sub.add_parser("string", help="Analyze entropy of a string or hex")
    e_str.add_argument("data", help="Input data")
    e_str.add_argument("--hex", action="store_true", help="Treat input as hex string")
    e_str.add_argument("--b64", action="store_true", help="Treat input as base64")

    e_file = ent_sub.add_parser("file", help="Analyze entropy of a file")
    e_file.add_argument("filepath", help="File to analyze")

    return parser

def main():
    print_banner()
    parser = build_parser()
    args = parser.parse_args()

    # ── HASH ──
    if args.module == "hash":
        if args.action == "identify":
            display_hash_identify(args.hash)

        elif args.action == "generate":
            hashes = compute_hashes(args.text)
            display_hashes(hashes)

        elif args.action == "file":
            if not os.path.isfile(args.filepath):
                console.print(f"[red]File not found:[/red] {args.filepath}")
                sys.exit(1)
            console.print(f"\n[dim]Computing hashes for:[/dim] [white]{args.filepath}[/white]")
            hashes = compute_file_hashes(args.filepath)
            display_hashes(hashes)

        elif args.action == "crack":
            inline_words: Optional[List[str]] = args.words if args.words else None
            result = crack_hash(args.hash, wordlist_path=args.wordlist,
                                words=inline_words,
                                algo=args.algo)
            display_crack_result(result)

    # ── STEGO ──
    elif args.module == "stego":
        if args.action == "analyze":
            if not os.path.isfile(args.image):
                console.print(f"[red]File not found:[/red] {args.image}")
                sys.exit(1)
            result = lsb_analysis(args.image)
            display_stego_result(result)
            if args.save_vis and "error" not in result:
                out = save_lsb_visualization(args.image, args.output)
                if RICH_AVAILABLE:
                    console.print(f"\n[green]LSB visualization saved:[/green] [white]{out}[/white]")
                else:
                    print(f"\nLSB visualization saved: {out}")

    # ── ENTROPY ──
    elif args.module == "entropy":
        if args.action == "string":
            raw = args.data
            if args.hex:
                try:
                    data = bytes.fromhex(raw.replace(" ", ""))
                    label = f"hex({raw[:20]}...)"
                except ValueError as e:
                    console.print(f"[red]Invalid hex:[/red] {e}")
                    sys.exit(1)
            elif args.b64:
                import base64
                try:
                    data = base64.b64decode(raw)
                    label = f"base64({raw[:20]}...)"
                except Exception as e:
                    console.print(f"[red]Invalid base64:[/red] {e}")
                    sys.exit(1)
            else:
                data = raw.encode("utf-8")
                label = f'"{raw[:40]}{"..." if len(raw)>40 else ""}"'
            result = analyze_entropy(data, label=label)
            display_entropy_result(result)

        elif args.action == "file":
            if not os.path.isfile(args.filepath):
                console.print(f"[red]File not found:[/red] {args.filepath}")
                sys.exit(1)
            result = analyze_entropy_file(args.filepath)
            display_entropy_result(result)

if __name__ == "__main__":
    main()