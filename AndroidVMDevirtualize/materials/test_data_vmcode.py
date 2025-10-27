#!/usr/bin/env python3
"""
Test string decryption on data.vmcode using discovered XOR key
"""

# Global XOR key discovered from data.vmcode at offset 0x1752f
KEY = b'\xab\x16+\xc0/D7\xb6\x7fQ1\x8f9@\x13\x11*\xec8\xdd7\xdaO"_T\x97\x00\x1d;\xa6T`\xad\xbfP\x8c\x86\xfeg\xc9\xc2\xaf\xaf_\xbaq\xc1\x9a6\x1bq.\xb6C3\n\xa5\xe5\xea\xf9 Y\xf1t\x11\x13%\xf2\x87\xd8\xb6\x8e\xcd\xa8#\xb3o\xd8NR\xe8\xbe\xd9\xc1\xa0j\xc2(Vw\xd9C\xfc\x92k\x0c#\xf8\xa9h\xb8\xf7\xd4$\xac\xad-\x88W\x92\x8a\xb3y\xcdYe\xd9\xab\xa8\xd1\x93\x87\x91o\xf5c\xeb\xa0\x05\xc7\xd4\xc6?\x80\xb9\xf5\xa3\xd0|\x7fO\n\'\xe1\xf5\xbe\x98\xb5\xd1\xd9P_lI\x18x\xa2\x16\xf8\xf7\xab\x03\xf0\xaf_\xe8\xf8\xf6\xce\xcc\r\xd2\xb3\xb4fO\xf2\xa9<\xd7\x0e\x04\x05\xa4\x85\xb5&\xcf\xbc\x16\xd3\xfe\x0b\xb8\xfa\xb1\xfb4\xf8\x16v\x92\x96\xe3\xee\x97\xf1\xc1\xad\x15\xe3\x0f\x18:^/\xfe\x14\x1a\xdd\x1b\xe9q\x11\xc8\xc3\xaa\xf2\xa0\xca"}\x91\xcd\xc8\x01_8H\xe9j\xbe\xf4\x1aB\xccm\xa2)\\\x1df\xb68'

def u16(data, offset):
    return data[offset] | (data[offset + 1] << 8)

def decode_string(data, offset, key):
    if offset + 2 > len(data):
        return None

    data_len = u16(data, offset)
    key_len = u16(key, 0)  # First 2 bytes of key

    length = (data_len ^ key_len) + 2

    if length < 3 or length > 1000:
        return None
    if offset + length > len(data):
        return None

    result = bytearray(length)
    for i in range(length):
        key_idx = i & 0xFF
        if key_idx >= len(key):
            key_idx = i % len(key)
        result[i] = data[offset + i] ^ key[key_idx]

    decoded = result[2:].decode('utf-8', errors='ignore')

    if all(c.isprintable() or c.isspace() for c in decoded):
        return decoded
    return None

def scan_strings(filename, key):
    with open(filename, 'rb') as f:
        data = f.read()

    print(f"File: {filename}")
    print(f"Size: {len(data)} bytes")
    print(f"Key length: {len(key)} bytes")
    print(f"Key first 2 bytes (length marker): {u16(key, 0)}")
    print("\n" + "="*60)
    print("Searching for strings (2-byte aligned scan)...")
    print("="*60 + "\n")

    found = []
    for offset in range(0, len(data) - 2, 2):  # 2-byte aligned
        result = decode_string(data, offset, key)
        if result and len(result) > 2:
            found.append((offset, result))

    for i, (offset, string) in enumerate(found[:50]):
        print(f"0x{offset:06x}: {string}")

    print(f"\n{'='*60}")
    print(f"Total strings found: {len(found)}")
    print("="*60)

    return found

if __name__ == '__main__':
    import sys

    filename = 'data.vmcode'
    if len(sys.argv) > 1:
        filename = sys.argv[1]

    try:
        strings = scan_strings(filename, KEY)
    except FileNotFoundError:
        print(f"Error: {filename} not found")
        sys.exit(1)
