## Introduction to tools and algorithms 

**Asymmetric Encryption Envelope Key** (AEEK) is part of Key Management Service (KMS) a cyber security system structure built from a series of Cryptography Modules and Encryption Algorithms and Key Decryption as the main security engine and container data integrity storage, which is created for the purpose of storing, managing, and controlling cryptographic keys. Made by binding (compiling) the cli and logic (core) with different programming languages, making the structure more complex and integrated.

AEEK builds a key data algorithm structure with a hybridization of different key algorithms (Key Encapsulation), making the key data management system not only centered on one key algorithm concept.

Building a sophisticated encryption system at the enterprise level requires designing a layered, robust, and scalable key management architecture and implementation protocol. I'll implement it with separate key variables, instead of the system operating with just one key. This key management protocol will be broadcast with DEK and KEK:

- **DEK** (**Data** **Encryption** **Key**): A unique symmetric key used to encrypt specific data.

- **KEK** (**Key** **Encryption** **Key**) / **Master** **Key** : The master key used only to encrypt the DEK.

### The Protocol (framework)

Imagine CLI will send secret JWT (nonce number) by chiper suite TLS 1.3 to database logic-engine:

Step 1 (Client/CLI Side - Encryption);
1. Create a random AES Key (32 bytes)
2. Data Encryption with AES-256-GCM using that key.
3. Get Public Key RSA/ECC Server property
4. Encrypt the AES Key using RSA-OAOEP/ECDH X25519
5. Send packet:```{ RSA_Encrypted_Key, AES_Encrypted_Data, AES_GCM_TAG }```

Step 2 (Backend Side - Decryption);
1. Server receives packet
2. Server uses RSA/ECC Private Key to open (decrypt) RSA-OAEP/ECDH X25519 → exit AES Key
3. The server uses the AES Key to unlock the original data.

> Noted: ECDH X25519 is carrying the concept of temporary keys or the shared secret derived from ECDH is stored in memory for the duration of the session. After the data is encrypted with AES.

### Mathematical Concept 

If D is data , ```K_{data}``` is DEK, and ```K_{master}``` is Master Key then:

- Data encryption: ```Ciphertext = Encryption(Kdata, D)```
- Key Encryption (Envelope): ```WrappedKey = Encryption(Kmaster, Kdata)```
- Save in database: ```{ Ciphertext, WrappedKey}```

Advantages: Kdata keys are never stored in *plaintext*, the ```Kmaster``` is securely stored in the HSM (Hardware-Security Module) or Key Management Service (Vault)

## JWE & mTLS

It is very important to implement JWE and TLS 1.3 (mTLS) on the Key Management Service architecture, considering that I am building a key encryption environment (Asymmetric Encryption) with using a security protocol that ensures authentication in both directions between the client and server, where both verify each other's identity using digital certificates before a connection is established. The use of JWE/JWT involves managing more private keys with user tokenization verifying certificates (Handshake protocol) After that, in the bandwidth tokenizer process, the user receives a public key which is used for verification. This method ensures that private files never leave the KMS environment

Framework The best way to implement an *interface* between CLI and Backend with built-in mTLS is to use gRPC Code Concept (gRPC Setup for mTLS) This is a piece of logic on how mTLS is setup on the Backend DB (Server) side.

For JWE (JSON Web Encryption) in this architecture, I use ```jwt-cpp``` or raw OpenSSL as above. However, since JWE is JSON, the flow will look like this:

- Client (CLI):
  - Get input data
  - Create JSON structure
  - Use Public Key Server (RSA) to encrypt AES Key (Like the ```rsa_wrap_key``` function in my previous code)
  - Send via gRPC

#### Gate API/UI Command Line Interface; API/UI applications that use interpreters or other languages such as C/Python (Shared Library)

***Hybrid*** approach like in this architecture which uses C++ to build "Core Logic" (brain) its use is of course due to the efficiency and inference character of the C++ interpreter fast and high security memory/storage 'data integrity' like the previous Envelopment Encryption Key

while the other languages such as Python provide more interactivity and ease of development "Interface/Orchestration" (body)

To do this, I will use the ```extern``` feature of C++ to keep the names and functions unchanged (*mangling name*) when compiled, so Python can call them using the library```ctypes``` on and on.

#### Compile into a Shared Library

On Linux/macOS (Terminal); use the ``-shared``` and ```-fPIC``` (Position Independent Code) flags.

```bash
g++ -shared -fPIC -o libcrypto_core.so crypto_lib.cpp -lssl -lcrypto
```

On windows (PowerShell/CMD with MinGW)

```cmd
g++ -shared -o libcrypto_core.dll crypto_lib.cpp -lssl -lcrypto
```

> Note: Make sure the path to OpenSSL is in the Windows environment variables.

## Hashing System (Argon2id)

In the previous code, I was still using ```RAND_bytes``` to generate random keys. This is fine for *Session Key or DEK*, but it is wrong if we want to generate a key from **User Password**.

I want this architecture's CLI to be able to log in or open a local database using the user's password, essentially as a client. We must convert the password to a 32-byte cryptographic value. using Argon2id

There are several reasons why Argon2id is superior to simply using random keys. Legacy algorithms (such as SHA-256, PBKDF2, and bcrypt) are vulnerable to GPU/ASIC attacks. The working concept of Argon2id forces attackers to use a lot of **RAM (Memory Hard)**, which is very difficult to hack en masse.

#### Scenario Illustration: user login for local file encryption

```python
    user_pass = "admin123_ss"
```

#### Change Password → AES Key (Argon2id)

```python
    derived_key, salt_used = vault.derive_key_from_password(user_pass)
    print(f"Derived Key (Hex): {derived_key.hex()}")
```

## Key Encapsulation: Hybrid Encryption with RSA-OAEP

RSA-OAEP is the gold standard of key encryption algorithms today because if we encrypt the *same* message twice with RSA-OAEP, the results will be *different* (this is due to the presence of adding random elements/salts in the padding) OAEP integrity ensures that if an attacker changes even one bit in the RSA ciphertext, the decryption process will fail completely and not leak any information).

Hybrid Encryption security system in this architecture:
1. AES-256-GCM used to encrypt data (Database) because it is very fast.
2. RSA-OAEP is used to encrypt the AES key itself.

Protocol Configuration:
- Protocols: TLS 1.3 (Data Transport System)
- Key Exchange: RSA-2048-OAEP (or ECC P-256)
- Data Encryption: AES-256-GCM 
- Hashing/KDF: Argon2id

#### input in/.env .example

```bash
 vault = SecureVault()
```

#### Interpretasi dan inisialisasi main-logic shared distribute

```cpp
    user_secret = "This is a $1M company secret"
    print(f"Input: {user_secret}")
    try:
        result = vault.encrypt(user_secret)
        
        print("\n[C++ Core Result]")
        print(f"Ciphertext : {result['ciphertext']}")
        print(f"IV (Nonce) : {result['iv']}")
        print(f"Auth Tag   : {result['tag']}")
        print("\nIntegrity Check: Valid (Generated by OpenSSL/C++)")
```

#### main interpreter

```cpp
        
    except Exception as e:
        print(f"Error: {e}")
```

#### output close/.env .example
```bash
    vault.close()
```

> Considering the use of KEK and DEK I will create a **modular variation of RSA OAEP** even though RSA is the gold standard Key Encryption Key in KMS infrastructure, RSA latency intensity is quite heavy, so in the future KMS will be *integrated by many servers for many needs*. I need to reconsider **compiling other key algorithm variations**. So, I'll probably create other modular algorithm keys for diversification. So specifically, the provisions depend on each individual's needs, 'what do you want to use this KMS for?'