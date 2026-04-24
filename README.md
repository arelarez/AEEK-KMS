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

## Integrated ECCX25519

There are several factors and reasons why I chose to replace RSA with ECC. Although RSA-2048 is also a very strong encryption method, there are some things to consider. RSA-2048 is large (256 bytes). ECC can compress it with greater strength. equivalent (Curve25519) uses a key of only 32 bytes. On the **Side Product** (e.g. mobile and IoT applications), ECC is much lighter than RSA in terms of CPU computation and battery usage efficiency. Modern protocols like Signal and TLS 1.3 prefer ECC (X25519) instead of RSA. Although this is optional, it basically depends on the protocol for which the KMS was created.

In RSA, we can simply: ```Encrypt(Public_Key, Data)```. But in ECC, the curve math doesn't work that way. We can't directly encrypt large amounts of data with ECC. We need the ECDH (Elliptic Curve Deffie-Hellman) or ECIES (Elliptic Curve Integrated Encryption Scheme) method.

Hybrid Encryption Key flow update (with ECCX25519):

1. Client (CLI): Create a temporary ECC key (Ephemeral Key pair)
2. Shared Secret: The client combines its temporary private key with the server's public key for shared secret distribution.
3. Wrapping: Use the Shared Secret (after hashing) to encrypt the AES Key.
4. Send: Client sends ```{ Ephemeral_Public_Key, Wrapped_AES_Key, Encrypted_Data }```
So the Server will do the reverse to get back the AES Key.

The method: AES Key Encryption uses Wrapping Key (In production, use AES-Key-Wrap RFC 3394, but XDR+Hash)

```python
        wrapping_key = bytes(shared_secret)
        aes_data_key = os.urandom(32)
        encrypted_packet = self.encrypt_aes_gcm(data, aes_data_key)
```

With the integration of the ECX25519, this architecture has achieved the level of "Perfect Forward Secrecy"

- Comparison description between RSA and ECC

   - In RSA If the Private Key Server is leaked in the next 5 years, the 'attacker' can describe all recorded past data.

   - But in ECC (With Epheremal) I create a new key (```my_priv```) every time I send data and immediately delete it, even if the server key is leaked in the future, the attacker cannot decrypt it.past session data. They need the ```my_priv``` that has been destroyed in RAM

#### Final Security Matrix
1. Transport: mTLS 1.3
2. Key Exchange: ECDH X25519 (Replacing RSA)
3. Encrypted Data: AES-256-GCM
4. Hashing: Argon2id

## re-explanation: Final KMS Architecture AEEK

This architecture was built using the principle of "Defense in Depth." I didn't rely on just one wall but instead created a series of layered walls, trenches, and traps.So technically why does this Hybrid Key (ECC + AES) and Distributed (Client-Side Encryption) approach frustrate existing cyber attack techniques,and why is this KMS so hard to Sniff and Penetrate and what are the other "hidden" benefits?

### Why Is It So Hard to Sniff? (Anti-Wiretapping)

In traditional architectures (which rely solely on SSL/HTTPS), hackers typically perform Man-in-the-Middle (MITM) attacks. They will intercept Wi-Fi connections or  spoofing SSL certificates.

- In this AEEK/AEEkms Architecture (v2.0):

   - Layer 1 (mTLS): Hackers cannot simply "intercept". Because the Backend server will request a certificate from the Client (CLI). If the attacker does not have valid client certificate (embedded in the obfuscated C++ binary), the connection is immediately terminated at the TCP Handshake level.

  - Layer 2 (Double Encryption): Let's create a scenario like how "the attacker managed to break into Layer 1 (for example by stealing the client certificate)". What do they see through sniffing? In fact, they only see the JWE/AES binary blob that was previously encrypted, leaving a trace on the user's laptop, and the attacker cannot see the client's password because the unlock key is in ephemeral memory (Epheremal ECC) and on a secure server, the result is that the sniffed data is 100% useless "garbage data".

### Why Is It So Hard to Penetrate? (Anti-Break Server)

This is the biggest advantage of "Decentralized Encryption" (Client-Side Encryption). Imagine the worst-case scenario: the backend server is completely hacked. The attacker gets into the database and does ```SELECT * FROM users```.

 - In *normal Architecture* Hacker can get user data, maybe password hashes, and sensitive **plaintext** data if encryption is only done on server disk.

 - However, in *Hybrid Encryption Architecture*, the database only contains a "Sealed Envelope" (AES Ciphertext). The attacker cannot find a "Magic Key" in the server code to unlock all the data. Each row of data locked with different DEK (Data Encryption Key), to open one envelope, an attacker must have access to the KMS (Key Management Service) which resides on a separate physical server (HSM). The important point is that because I use ECC Epheremal, the session key for the previous communication is **lost**. The attacker cannot decipher the key.Past Traffic Logs.

### Other Benefits Besides Security 

Besides giving Attackers a headache, this architecture provides tremendous business and technical advantages.

#### Perfect Forward Secrecy (PFS) 

- at RSA If the Attacker records the Victim's internet traffic (they do it without being able to see or read it), if it takes them another 5 years for a better attack tool,  They managed to steal the Private Key Server, and opened the traffic records from 5 years ago.

- The solution I created with ECC Epheremal, because the key is created suddenly (```generate_ecc_keypair```) and immediately deleted from RAM after use, The traffic will be **forever secure**. Even if the server is compromised in the future, the past keys will never be there to be stolen.

#### Server Resource Savings (Cost Efficiency; Centralized vs. Distributed)

- Centralized: The server must encrypt/decrypt data for 10,000 users simultaneously. The server's CPU will be overwhelmed by this process on a regular basis.

- Distributed: The encryption load (AES-GCM & Argon2id) is carried out on the User's Laptop/HP (Client). The server only receives mature data, this will save cloud/server rental costs significantly.

#### Legal Compliance (Compliance & GDPR)

If we store banking or health data

- Regulators will ask: "Can your database admin peek into the customer database?"

- With this Architecture, the answer is; "No" Even the database admin who manages the client data itself will only see *Chipertext*.

#### Data Integrity (Anti-Tampering)

Remember the GMAC (Tag) in AES-GCM. If an attacker accidentally changes the balance of ```1,000,000``` to ```9,000,000``` in the database (without knowing the key), when the application tries to decrypt, h The result is not a messed up number, but rather ERROR: Decryption Failed
The system will automatically know that the data has been tampered with and reject it.

### Conclusion 

This architecture is the highest privacy standard currently available. This KMS protects users, even from the database administrator, or "me as the author".

If you find this work useful, please cite it:

```bibtex
@software{AEEK,
  author = {Arel Bachtiar},
  title = {AEEK/AEEK-KMS},
  year = {2026},
  url = {[AEEK-KMS](https://github.com/arelarez/AEEK-KMS)}
}
```