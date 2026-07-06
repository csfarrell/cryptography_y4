# Cryptography & Security Protocols
Cryptography projects for year 4 of Comsci

## Assignment1.java
Symmetric File Encryption Using Password and Salt
3 week long assignment to perform symmetric encryption of a file using the block cipher AES, in which:
- The key is derived from a password and a salt.
- The password is encoded using UTF-8 (considered strong)
- Salt is randomly generated (128-bit)
- Password and salt concatenated together and hashed 200 times using SHA-256
- Resulting digest (H^200(p||s)) is used as AES key
- Input binary file is encrypted using AES in CBC mode with key and block size of 128 bits
- IV for encryption is randomly generated (128-bit)
- Final parts of message accounted for in terms of going over or below block size
- Password is encrypted using RSA with encryption exponent and given public modulus
- This was using my own implementation of modular exponentiation
This assignment was completed on time and to a high standard
Mark: 15/15

## Assignment2.java
Digital Signature Using ElGamal
3 week long assignment to perform a digital signature using the ElGamal signature scheme
- Given a prime modulus p and generator g
- Generating a public/private ElGamal key pair
- Signing the message m
This assignment was completed on time and to a high standard
Mark: 15/15 (Signature and Modular Inverse work correctly)
