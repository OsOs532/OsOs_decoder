#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Universal Decoder & Hash Cracker
Prints 'OsOs' on start, tries many decodings and can crack common hashes using a wordlist.
Supports: ASCII, Hex, Binary, Base64, Base32, URL, Quoted-Printable, HTML entities, Uuencoding, ROT13.
Cracks: md5, sha1, sha256, sha512, md5crypt, sha256_crypt, sha512_crypt, bcrypt, lm, ntlm, mysql5
"""

import base64
import binascii
import quopri
import urllib.parse
import html
import hashlib
import re
import sys

try:
    from passlib.hash import md5_crypt, sha256_crypt, sha512_crypt, bcrypt as passlib_bcrypt, lmhash, nthash
    PASSLIB = True
except Exception:
    PASSLIB = False

BANNER = """
.d88888b.                 .d88888b.                
d88P" "Y88b               d88P" "Y88b               
888     888               888     888               
888     888 .d8888b       888     888 .d8888b       
888     888 88K           888     888 88K           
888     888 "Y8888b.      888     888 "Y8888b.      
Y88b. .d88P      X88      Y88b. .d88P      X88      
 "Y88888P"   88888P'       "Y88888P"   88888P'      

           OsOs Decoder v2.0
"""

# ------------------ decoders ------------------
def decode_ascii(text):
    try:
        parts = re.split(r'[\s,;:]+', text.strip())
        if len(parts) >= 1 and all(p.isdigit() for p in parts):
            return ''.join(chr(int(p)) for p in parts)
    except:
        pass
    return None

def decode_hex(text):
    try:
        s = re.sub(r'0x', '', text, flags=re.IGNORECASE)
        s = re.sub(r'[^0-9a-fA-F]', '', s)
        if len(s) % 2 != 0:
            s = '0' + s
        return bytes.fromhex(s).decode('utf-8')
    except:
        return None

def decode_binary(text):
    try:
        parts = re.split(r'[\s,]+', text.strip())
        if all(re.fullmatch(r'[01]{8,}', p) for p in parts):
            return ''.join(chr(int(p, 2)) for p in parts)
        s = re.sub(r'[^01]', '', text)
        if len(s) % 8 == 0:
            return ''.join(chr(int(s[i:i+8], 2)) for i in range(0, len(s), 8))
    except:
        pass
    return None

def decode_base64(text):
    try:
        s = re.sub(r'[^A-Za-z0-9+/=]', '', text)
        padding_needed = (4 - len(s) % 4) % 4
        s += '=' * padding_needed
        return base64.b64decode(s).decode('utf-8')
    except:
        return None

def decode_base32(text):
    try:
        s = re.sub(r'[^A-Z2-7=]', '', text.upper())
        padding_needed = (8 - len(s) % 8) % 8
        s += '=' * padding_needed
        return base64.b32decode(s).decode('utf-8')
    except:
        return None

def decode_url(text):
    try:
        dec = urllib.parse.unquote(text)
        return dec if dec != text else None
    except:
        return None

def decode_quoted_printable(text):
    try:
        return quopri.decodestring(text).decode('utf-8')
    except:
        return None

def decode_html_entities(text):
    try:
        dec = html.unescape(text)
        return dec if dec != text else None
    except:
        return None

def decode_uuencoding(text):
    try:
        return binascii.a2b_uu(text).decode('utf-8')
    except:
        return None

def decode_rot13(text):
    try:
        import codecs
        return codecs.decode(text, 'rot_13')
    except:
        return None

# ------------------ hash detection ------------------
def detect_hash_type(h):
    h = h.strip()
    if re.fullmatch(r'\*[0-9A-Fa-f]{40}', h):
        return 'mysql5'
    if h.startswith('$2'):
        return 'bcrypt'
    if h.startswith('$1$'):
        return 'md5crypt'
    if h.startswith('$5$'):
        return 'sha256_crypt'
    if h.startswith('$6$'):
        return 'sha512_crypt'
    if re.fullmatch(r'[0-9a-fA-F]{32}', h):
        return 'ambiguous32'
    if re.fullmatch(r'[0-9a-fA-F]{40}', h):
        return 'sha1'
    if re.fullmatch(r'[0-9a-fA-F]{64}', h):
        return 'sha256'
    if re.fullmatch(r'[0-9a-fA-F]{128}', h):
        return 'sha512'
    return None

def ntlm_hash_of(pw):
    try:
        md4 = hashlib.new('md4')
        md4.update(pw.encode('utf-16le'))
        return md4.hexdigest()
    except:
        return None

# ------------------ cracking ------------------
def verify_raw(candidate, target, algo):
    algo = algo.lower()
    if algo == 'md5':
        return hashlib.md5(candidate.encode()).hexdigest().lower() == target.lower()
    if algo == 'sha1':
        return hashlib.sha1(candidate.encode()).hexdigest().lower() == target.lower()
    if algo == 'sha256':
        return hashlib.sha256(candidate.encode()).hexdigest().lower() == target.lower()
    if algo == 'sha512':
        return hashlib.sha512(candidate.encode()).hexdigest().lower() == target.lower()
    return False

def verify_mysql5(candidate, target):
    try:
        inner = hashlib.sha1(candidate.encode()).digest()
        outer = hashlib.sha1(inner).hexdigest().upper()
        return ('*' + outer) == target.upper()
    except:
        return False

def verify_ntlm(candidate, target):
    t = target.lower()
    if PASSLIB:
        try:
            return nthash.verify(candidate, target)
        except:
            pass
    try:
        md4 = hashlib.new('md4')
        md4.update(candidate.encode('utf-16le'))
        return md4.hexdigest().lower() == t
    except:
        return False

def verify_lm(candidate, target):
    if PASSLIB:
        try:
            return lmhash.verify(candidate, target)
        except:
            pass
    return False

def verify_crypt(candidate, target, ctype):
    if not PASSLIB:
        return False
    try:
        if ctype == 'md5crypt':
            return md5_crypt.verify(candidate, target)
        if ctype == 'sha256_crypt':
            return sha256_crypt.verify(candidate, target)
        if ctype == 'sha512_crypt':
            return sha512_crypt.verify(candidate, target)
        if ctype == 'bcrypt':
            return passlib_bcrypt.verify(candidate, target)
    except:
        return False
    return False

def crack_with_wordlist(target, wordlist_path, types_to_try=None, threads=8, limit=None):
    if types_to_try is None:
        types_to_try = []
    try:
        f = open(wordlist_path, 'r', encoding='utf-8', errors='ignore')
    except FileNotFoundError:
        print(f"[!] Wordlist not found: {wordlist_path}")
        return None

    from concurrent.futures import ThreadPoolExecutor
    pool = ThreadPoolExecutor(max_workers=threads)

    def attempts():
        for i, line in enumerate(f):
            if limit and i >= limit:
                break
            yield line.rstrip('\n')

    futures = {}
    try:
        for cand in attempts():
            for typ in types_to_try:
                if typ in ('md5','sha1','sha256','sha512'):
                    futures[pool.submit(verify_raw, cand, target, typ)] = (cand, typ)
                elif typ == 'mysql5':
                    futures[pool.submit(verify_mysql5, cand, target)] = (cand, typ)
                elif typ == 'ntlm':
                    futures[pool.submit(verify_ntlm, cand, target)] = (cand, typ)
                elif typ == 'lm':
                    futures[pool.submit(verify_lm, cand, target)] = (cand, typ)
                elif typ in ('md5crypt','sha256_crypt','sha512_crypt','bcrypt'):
                    futures[pool.submit(verify_crypt, cand, target, typ)] = (cand, typ)

            done_now = [fut for fut in futures if fut.done()]
            for fut in done_now:
                try:
                    ok = fut.result()
                    cand, typ = futures.pop(fut)
                    if ok:
                        pool.shutdown(wait=False)
                        f.close()
                        return cand, typ
                except:
                    futures.pop(fut, None)
    finally:
        pool.shutdown(wait=False)
        f.close()
    return None

# ------------------ main interactive flow ------------------
def main():
    print(BANNER)
    try:
        s = input("Enter the encoded text or hash: ").strip()
    except KeyboardInterrupt:
        print("\nBye.")
        sys.exit(0)

    decoders = [
        ('ASCII', decode_ascii),
        ('Hex', decode_hex),
        ('Binary', decode_binary),
        ('Base64', decode_base64),
        ('Base32', decode_base32),
        ('URL', decode_url),
        ('Quoted-Printable', decode_quoted_printable),
        ('HTML entities', decode_html_entities),
        ('Uuencoding', decode_uuencoding),
        ('ROT13', decode_rot13)
    ]

    print("\n[+] Decoding attempts:")
    any_found = False
    for name, fn in decoders:
        try:
            res = fn(s)
            if res:
                print(f"  - {name}: {res}")
                any_found = True
        except:
            pass
    if not any_found:
        print("  (no simple textual decoding found)")

    htype = detect_hash_type(s)
    if htype:
        if htype == 'ambiguous32':
            print("\n[!] Input is 32-hex: could be MD5, NTLM or LM.")
            chosen = input("Which to try? (md5/ntlm/lm/all) [all]: ").strip().lower() or 'all'
            if chosen == 'all':
                types = ['md5','ntlm','lm']
            else:
                types = [chosen]
        else:
            print(f"\n[+] Detected likely hash type: {htype}")
            if htype in ('md5','sha1','sha256','sha512'):
                types = [htype]
            elif htype in ('mysql5','md5crypt','bcrypt','sha256_crypt','sha512_crypt'):
                types = [htype]
            else:
                types = [htype]
        want = input("Do you want to try cracking it with a wordlist now? (y/n): ").strip().lower()
        if want == 'y':
            wl = input("Enter path to wordlist: ").strip()
            threads = input("Threads? [default 8]: ").strip()
            try:
                threads = int(threads) if threads else 8
            except:
                threads = 8
            limit = input("Limit lines? (0 = no limit): ").strip()
            try:
                limit = int(limit) if limit else 0
            except:
                limit = 0
            print("[*] Starting cracking...")
            res = crack_with_wordlist(s, wl, types_to_try=types, threads=threads, limit=(limit or None))
            if res:
                pw, used = res
                print(f"[+] SUCCESS: type={used} password='{pw}'")
            else:
                print("[!] No match found in wordlist for selected types.")
    else:
        want = input("\nDo you want to attempt hash cracking anyway? (y/n): ").strip().lower()
        if want == 'y':
            chosen = input("Which hash types to try? (comma separated, options: md5,sha1,sha256,sha512,md5crypt,sha256_crypt,sha512_crypt,bcrypt,ntlm,lm,mysql5)\nEnter 'all' to try many: ").strip().lower()
            if chosen == 'all':
                types = ['md5','sha1','sha256','sha512','md5crypt','sha256_crypt','sha512_crypt','bcrypt','ntlm','lm','mysql5']
            else:
                types = [t.strip() for t in chosen.split(',') if t.strip()]
            wl = input("Enter path to wordlist: ").strip()
            threads = input("Threads? [default 8]: ").strip()
            try:
                threads = int(threads) if threads else 8
            except:
                threads = 8
            limit = input("Limit lines? (0 = no limit): ").strip()
            try:
                limit = int(limit) if limit else 0
            except:
                limit = 0
            print("[*] Starting cracking...")
            res = crack_with_wordlist(s, wl, types_to_try=types, threads=threads, limit=(limit or None))
            if res:
                pw, used = res
                print(f"[+] SUCCESS: type={used} password='{pw}'")
            else:
                print("[!] No match found in wordlist.")
    print("\nDone.")

if __name__ == '__main__':
    main()
