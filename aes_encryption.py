from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os
import argparse

BLOCK_SIZE = AES.block_size

def pad(data):
    return data + b"\0" * (BLOCK_SIZE - len(data) % BLOCK_SIZE)

def encrypt_file(key, input_file, output_file):
    cipher = AES.new(key, AES.MODE_CBC)
    with open(input_file, 'rb') as f:
        plaintext = pad(f.read())
    with open(output_file, 'wb') as f:
        f.write(cipher.iv + cipher.encrypt(plaintext))
    print(f"Encrypted: {output_file}")

def decrypt_file(key, input_file, output_file):
    with open(input_file, 'rb') as f:
        iv = f.read(16)
        ciphertext = f.read()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext).rstrip(b'\0')
    with open(output_file, 'wb') as f:
        f.write(plaintext)
    print(f"Decrypted: {output_file}")

def main():
    parser = argparse.ArgumentParser(description='AES File Encryption Tool')
    parser.add_argument('mode', choices=['encrypt', 'decrypt'], help='Choose mode')
    parser.add_argument('input', help='Input file')
    parser.add_argument('output', help='Output file')
    parser.add_argument('--key', help='Encryption key (16 characters)', required=True)

    args = parser.parse_args()
    key = args.key.encode('utf-8')

    if len(key) != 16:
        raise ValueError("Key must be 16 characters long.")

    if args.mode == 'encrypt':
        encrypt_file(key, args.input, args.output)
    elif args.mode == 'decrypt':
        decrypt_file(key, args.input, args.output)

if __name__ == '__main__':
    main()
