# CryptoForensics Suite v2.0

Advanced Cryptography & Digital Forensics Tool for Linux.

```
  ██████╗██████╗ ██╗   ██╗██████╗ ████████╗ ██████╗ 
 ██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝██╔═══██╗
 ██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   ██║   ██║
 ██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   ██║   ██║
 ╚██████╗██║  ██║   ██║   ██║        ██║   ╚██████╔╝
  ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝    ╚═════╝ 
```

> ⚠ For legal use only — ethical hacking, CTF, penetration testing with authorization.

---

## Installation

```bash
git clone <repo>
cd cryptoforensics
chmod +x install.sh
./install.sh
source ~/.bashrc    
```

---

## Modules

### [01] Hash Analyzer

**Identify** hash type from string:
```bash
cryptoforensics hash identify 5f4dcc3b5aa765d61d8327deb882cf99
```
Detects: MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, NTLM, bcrypt, MySQL, RIPEMD-160, BLAKE2, Keccak, SHA-3, Linux crypt formats.

**Generate** all hashes for a plaintext:
```bash
cryptoforensics hash generate "password123"
```
Outputs: MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-512, BLAKE2b, BLAKE2s.

**Hash a file:**
```bash
cryptoforensics hash file /path/to/file.iso
```

**Crack** with dictionary attack:
```bash

cryptoforensics hash crack 5f4dcc3b5aa765d61d8327deb882cf99 --wordlist rockyou.txt

# Specify algorithm manually
cryptoforensics hash crack <hash> --wordlist list.txt --algo sha256

# Inline word list
cryptoforensics hash crack <hash> --words password admin 123456 letmein
```

Supported algorithms: `md5`, `sha1`, `sha224`, `sha256`, `sha384`, `sha512`, `sha3_256`, `sha3_512`.

---

### [02] Steganography Detector — LSB Analysis

```bash

cryptoforensics stego analyze image.png


cryptoforensics stego analyze image.png --save-vis


cryptoforensics stego analyze image.png --save-vis --output lsb_out.png
```

**What it does:**
- Per-channel LSB bit analysis (R, G, B)
- Chi-squared test for LSB uniformity (statistical indicator of stego)
- Bit-pair entropy analysis
- LSB capacity calculation
- Attempts ASCII decode of LSB stream
- Saves amplified LSB visualization (LSB×128) to PNG
- Suspicion score 0–21 with verdict: CLEAN / LOW / MEDIUM / HIGH

Requires Pillow: `pip install Pillow`

---

### [03] Entropy Analyzer

**String analysis:**
```bash
cryptoforensics entropy string "Hello, World!"

# Hex input
cryptoforensics entropy string "aabbccddeeff0011" --hex

# Base64 input
cryptoforensics entropy string "SGVsbG8gV29ybGQ=" --b64
```

**File analysis:**
```bash
cryptoforensics entropy file /path/to/suspicious.bin
cryptoforensics entropy file /path/to/archive.zip
cryptoforensics entropy file /path/to/malware_sample.exe
```

**Output includes:**
- Shannon entropy (bits/byte) with visual bar
- Unique byte ratio across 256 byte space
- Printable character ratio
- Chi-squared test for randomness
- Block-level entropy profile (64-byte blocks) as sparkline
- Top 16 most frequent bytes
- **Automatic classification:**
  - `ENCRYPTED / RANDOM` — entropy ≥ 7.5 (AES, ChaCha20, OTP)
  - `COMPRESSED / PACKED` — entropy ≥ 7.0 (ZIP, UPX-packed ELF)
  - `BINARY / MIXED` — entropy ≥ 6.0 (compiled code, mixed content)
  - `NATURAL LANGUAGE` — entropy 4–6, high printable ratio
  - `LOW COMPLEXITY` — entropy < 2.0 (repetitive, padding, nulls)
  - `STRUCTURED DATA` — JSON, XML, CSV

---

## Dependencies

| Package | Purpose                      | Required |
|---------|------------------------------|----------|
| Python 3.8+ | Core runtime             | ✓ Yes    |
| `rich`  | Terminal UI                  | Optional |
| `Pillow`| Steganography image analysis | For stego|

Install manually:
```bash
pip install rich Pillow
```

---

## Common Wordlists

| Wordlist     | Size     | Download |
|--------------|----------|---------|
| rockyou.txt  | 133 MB   | Kali Linux: `/usr/share/wordlists/rockyou.txt.gz` |
| SecLists     | Various  | `git clone https://github.com/danielmiessler/SecLists` |

On Kali:
```bash
gunzip /usr/share/wordlists/rockyou.txt.gz
cryptoforensics hash crack <hash> --wordlist /usr/share/wordlists/rockyou.txt
```

---

## Examples

```bash
# Full hash pipeline on a file
cryptoforensics hash file /etc/passwd

# Identify a SHA-256 hash
cryptoforensics hash identify a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3

# Check if image has hidden data
cryptoforensics stego analyze suspicious.png --save-vis

# Classify a binary file
cryptoforensics entropy file malware.bin

# Detect encrypted archive
cryptoforensics entropy file secret.zip
```

---

## License

MIT — For authorized security testing, CTF competitions, and educational purposes only.
