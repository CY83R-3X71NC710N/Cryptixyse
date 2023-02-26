
#!/usr/bin/env python
# CY83R-3X71NC710N © 2023

"""
Cryptixyse is an advanced encryption and decryption system that utilizes elliptic curve cryptography for increased security.
It utilizes libraries such as Crypto and PyCryptodome to generate the keys and encrypt and decrypt the data for highest security.
It also uses SHA-256 for further hashing. This script is cross-platform and extensible.
"""

import os
import base64
import hashlib

from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import DSS
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2

# Generate an elliptic curve key
def generate_key():
    private_key = ECC.generate(curve='P-256')
    return private_key

# Encrypt the data using AES
def encrypt_data(data, key):
    # Generate a random key to use with AES
    aes_key = get_random_bytes(32)
    # Encrypt the data using AES
    cipher = AES.new(aes_key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
    iv = b64encode(cipher.iv)
    # Encrypt the AES key using the public key
    cipher_rsa = PKCS1_OAEP.new(key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    # Return the encrypted data and the encrypted AES key
    return ct_bytes, encrypted_aes_key, iv

# Decrypt the data using AES
def decrypt_data(data, key, iv):
    # Decrypt the AES key using the private key
    cipher_rsa = PKCS1_OAEP.new(key)
    decrypted_aes_key = cipher_rsa.decrypt(data[1])
    # Decrypt the data using AES
    cipher = AES.new(decrypted_aes_key, AES.MODE_CBC, b64decode(iv))
    pt = unpad(cipher.decrypt(data[0]), AES.block_size)
    return pt.decode('utf-8')

# Generate a SHA-256 hash
def generate_hash(data):
    sha256_hash = hashlib.sha256(data.encode('utf-8')).hexdigest()
    return sha256_hash

# Encode data in base64
def b64encode(data):
    encoded_data = base64.b64encode(data).decode('utf-8')
    return encoded_data

# Decode data from base64
def b64decode(data):
    decoded_data = base64.b64decode(data)
    return decoded_data

# Generate a signature using the private key
def generate_signature(key, data):
    h = SHA256.new(data.encode('utf-8'))
    signer = DSS.new(key, 'fips-186-3')
    signature = signer.sign(h)
    return signature

# Verify the signature using the public key
def verify_signature(key, signature, data):
    h = SHA256.new(data.encode('utf-8'))
    verifier = DSS.new(key, 'fips-186-3')
    try:
        verifier.verify(h, signature)
        return True
    except ValueError:
        return False

# Generate a PBKDF2 key
def generate_pbkdf2_key(password, salt):
    key = PBKDF2(password, salt)
    return key

# Main function
def main():
    # Generate an elliptic curve key
    private_key = generate_key()
    # Get the public key from the private key
    public_key = private_key.public_key()
    # Get the data to encrypt
    data = input("Enter the data to encrypt: ")
    # Encrypt the data
    encrypted_data = encrypt_data(data, public_key)
    # Generate a SHA-256 hash
    sha256_hash = generate_hash(data)
    # Generate a signature
    signature = generate_signature(private_key, sha256_hash)
    # Verify the signature
    is_verified = verify_signature(public_key, signature, sha256_hash)
    # Print the results
    print("Encrypted data:", encrypted_data)
    print("SHA-256 hash:", sha256_hash)
    print("Signature:", signature)
    print("Signature verified:", is_verified)

if __name__ == '__main__':
    main()
