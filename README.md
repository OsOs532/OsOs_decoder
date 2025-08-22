# OsOs Decoder

**OsOs Decoder** is an interactive script for decoding various encodings and cracking common hashes using a wordlist.

---

## Features

- Supports decoding the following formats:
  - ASCII
  - Hex
  - Binary
  - Base64
  - Base32
  - URL
  - Quoted-Printable
  - HTML entities
  - Uuencoding
  - ROT13
- Detects likely hash types:
  - MD5, SHA1, SHA256, SHA512
  - NTLM, LM
  - MySQL5
  - md5crypt, sha256_crypt, sha512_crypt, bcrypt
- Can attempt to crack hashes using a wordlist.
- Integrates with `passlib` for advanced hash types if available.

---

## Usage

1. Download the script:
```bash
wget https://raw.githubusercontent.com/OsOs532/OsOs_decoder/main/ososdecoding.py
Run the script:
python3 ososdecoding.py
