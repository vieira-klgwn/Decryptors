#!/usr/bin/env python3
"""
extract_and_try_decrypt.py

Usage:
    python3 extract_and_try_decrypt.py <input_file>

<input_file> may be:
 - a binary file (raw bytes)
 - a hexdump-like text file (lines like: "0000  31 20 31 39 37 37 ... | 1 1977 ... |")

The script:
 - parses the input into raw bytes
 - prints printable ASCII sequences found (for inspection)
 - searches for base64-like substrings and probable Fernet tokens (start with 'gAAAA')
 - attempts Base64-decoding and Fernet decryption using 'encryption_key.key' in cwd
 - saves a successful decryption to decrypted_message.txt
"""

import sys
import re
import base64
from binascii import unhexlify
from cryptography.fernet import Fernet

PRINT_MIN_LEN = 4        # min length for an ASCII printable segment to show
BASE64_MIN_LEN = 32      # minimum length for a base64 candidate
FERNET_PREFIX = b"gAAAA" # common Fernet prefix in base64 tokens

def read_input_as_bytes(path):
    """
    Read the file. If it looks like a textual hexdump (lines with hex bytes),
    extract hex byte pairs and return bytes. Otherwise return raw file bytes.
    """
    with open(path, "rb") as f:
        raw = f.read()

    # Try decode to text to detect hexdump-like content
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        # Not a text file -> treat as binary
        return raw

    # Heuristic: if the text contains many 2-hex sequences, parse as hexdump
    hex_pairs = re.findall(r'\b[0-9a-fA-F]{2}\b', text)
    if len(hex_pairs) >= 20:  # heuristic threshold
        hex_bytes = bytes(int(h, 16) for h in hex_pairs)
        return hex_bytes

    # If not a hexdump, treat as textual bytes (return original bytes)
    return raw

def find_printable_segments(b):
    """
    Return a list of printable ASCII segments of length >= PRINT_MIN_LEN.
    """
    s = ''.join((chr(c) if 32 <= c <= 126 else '\n') for c in b)
    segs = [seg for seg in s.splitlines() if len(seg) >= PRINT_MIN_LEN]
    return segs

def find_base64_candidates_from_printables(segs):
    """
    From printable segments, find base64-like substrings via regex.
    """
    candidates = set()
    # base64 charset: A-Z a-z 0-9 + / =
    b64_re = re.compile(r'([A-Za-z0-9+/=]{%d,})' % BASE64_MIN_LEN)
    for seg in segs:
        for m in b64_re.finditer(seg):
            cand = m.group(1)
            # Strip leading/trailing '=' that are padding-only extremes (keep internal)
            cand = cand.strip()
            candidates.add(cand)
    return list(candidates)

def find_base64_candidates_in_bytes(b):
    """
    Search raw bytes for substrings that look like base64 (ASCII subset).
    This will find tokens that may be split by non-printable bytes if they are contiguous ASCII.
    """
    ascii_view = ''.join((chr(c) if 32 <= c <= 126 else ' ') for c in b)
    return find_base64_candidates_from_printables(ascii_view.splitlines())

def find_fernet_like_tokens(b):
    """
    Search raw bytes for tokens starting with 'gAAAA' (Fernet signature).
    Extract contiguous run of base64 characters following the prefix.
    """
    tokens = []
    # Find positions of the ASCII prefix
    for m in re.finditer(b"gAAAA", b):
        start = m.start()
        # expand forward while byte is base64 char (A-Za-z0-9+/=)
        allowed = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
        end = start
        while end < len(b) and b[end:end+1] in allowed:
            end += 1
        token = b[start:end]
        if len(token) >= 32:
            try:
                token_str = token.decode("ascii")
                tokens.append(token_str)
            except Exception:
                pass
    return tokens

def try_decrypt_candidate(candidate_str, fernet):
    """
    Try base64-decoding and decrypting candidate with Fernet.
    Returns decrypted bytes on success or raises.
    """
    # Candidate might already be base64 bytes that include newlines/padding
    # Normalize: remove whitespace
    cand_clean = re.sub(r'\s+', '', candidate_str)
    # Ensure proper padding for base64 (but Fernet tokens are proper)
    try:
        decoded = base64.b64decode(cand_clean, validate=True)
    except Exception:
        # not a valid base64 (skip)
        raise

    # Try decrypt with Fernet (it expects the base64 token string as bytes originally)
    # Fernet.decrypt expects the *base64 token* (as bytes or str), not the raw decoded bytes.
    # So pass the original base64 token as bytes.
    try:
        # fernet expects token as bytes
        decrypted = fernet.decrypt(cand_clean.encode('ascii'))
        return decrypted
    except Exception as e:
        raise

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 extract_and_try_decrypt.py <input_file>")
        sys.exit(1)

    input_path = sys.argv[1]

    try:
        data = read_input_as_bytes(input_path)
    except Exception as e:
        print("Error reading input:", e)
        sys.exit(1)

    print(f"[i] Read {len(data)} bytes from {input_path}")

    # 1) show printable ASCII segments
    print("\n--- Printable ASCII segments (len >= %d) ---" % PRINT_MIN_LEN)
    segs = find_printable_segments(data)
    for i, s in enumerate(segs[:50], 1):  # limit to first 50 segments
        print(f"{i:02d}) {s}")

    # 2) find base64-like candidates from printable segments
    b64_candidates = find_base64_candidates_from_printables(segs)
    # also search entire bytes as fallback
    b64_candidates += find_base64_candidates_in_bytes(data)
    b64_candidates = list(dict.fromkeys(b64_candidates))  # unique, preserve order

    print("\n--- Base64-like candidates found (>= %d chars) ---" % BASE64_MIN_LEN)
    if not b64_candidates:
        print("None found by printable search.")
    else:
        for i, c in enumerate(b64_candidates, 1):
            print(f"{i:02d}) len={len(c)} -> start: {c[:40]}...")

    # 3) find fernet-like tokens by scanning raw bytes for 'gAAAA' prefix
    fernet_tokens = find_fernet_like_tokens(data)
    print("\n--- Fernet-like tokens discovered in raw bytes ---")
    if not fernet_tokens:
        print("None found.")
    else:
        for i, t in enumerate(fernet_tokens, 1):
            print(f"{i:02d}) len={len(t)} -> start: {t[:40]}...")

    # Combine candidates: try Fernet-like tokens first, then base64 candidates
    candidates = []
    candidates += fernet_tokens
    candidates += [c for c in b64_candidates if c not in fernet_tokens]

    # 4) load Fernet key
    try:
        with open("encryption_key.key", "rb") as kf:
            key = kf.read().strip()
            fernet = Fernet(key)
        print("\n[i] Loaded Fernet key from 'encryption_key.key'.")
    except FileNotFoundError:
        print("\n[!] encryption_key.key not found. Skipping decryption attempts.")
        fernet = None
    except Exception as e:
        print("\n[!] Failed to load Fernet key:", e)
        fernet = None

    # 5) try decrypting each candidate (if we have a key)
    success = False
    if fernet and candidates:
        print("\n--- Trying to decrypt candidates with Fernet ---")
        for i, cand in enumerate(candidates, 1):
            print(f"\nAttempt {i}: candidate length {len(cand)} start: {cand[:60]}...")
            try:
                decrypted = try_decrypt_candidate(cand, fernet)
                print("[✓] Decryption successful!")
                try:
                    text = decrypted.decode("utf-8")
                    print("Decrypted (utf-8):\n", text)
                except Exception:
                    print("Decrypted bytes (non-UTF8):", decrypted)
                # save to file
                with open("decrypted_message.txt", "wb") as out:
                    out.write(decrypted)
                print("[✓] Saved decrypted payload to decrypted_message.txt")
                success = True
                break
            except Exception as e:
                print("[✗] This candidate failed to decrypt:", str(e))
    else:
        print("\n[!] No Fernet key or no candidates to try decryption.")

    if not success:
        print("\n[-] No successful Fernet decryptions found.")
        print("If you expected a Fernet token, ensure the input contains the base64 token (ASCII) and that 'encryption_key.key' is the correct key.")
        print("You can also try preprocessing the image and re-extracting bytes (cropping/deskewing).")

if __name__ == "__main__":
    main()
