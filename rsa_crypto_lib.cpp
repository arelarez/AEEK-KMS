#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/kdf.h>
#include <openssl/params.h>

class CryptoCore {

public:
    int derive_key_argon2id(const char* password, 
                            const unsigned char* salt, int salt_len,
                            unsigned char* out_key) {
        
        EVP_KDF *kdf = EVP_KDF_fetch(NULL, "ARGON2ID", NULL);
        if (kdf == NULL) return 0;
        
        EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
        EVP_KDF_free(kdf); // Template sudah tidak dipakai
        if (kctx == NULL) return 0;

        uint64_t memory_cost = 64 * 1024; 
        uint64_t iterations = 3;
        uint32_t parallelism = 4;
        
        OSSL_PARAM params[6];
        OSSL_PARAM *p = params;

        *p++ = OSSL_PARAM_construct_octet_string("pass", (void*)password, strlen(password));
        *p++ = OSSL_PARAM_construct_octet_string("salt", (void*)salt, salt_len);
        *p++ = OSSL_PARAM_construct_uint64("iter", &iterations);
        *p++ = OSSL_PARAM_construct_uint64("memcost", &memory_cost);
        *p++ = OSSL_PARAM_construct_uint32("lanes", &parallelism); // Lanes = Threads
        *p++ = OSSL_PARAM_construct_end();

        int ret = EVP_KDF_derive(kctx, out_key, 32, params);

        EVP_KDF_CTX_free(kctx);
        
        if (ret <= 0) return 0; // Gagal
        return 1; // Sukses
    }
};

extern "C" {
    int Crypto_DeriveKey(CryptoCore* ptr, 
                         const char* password, 
                         const unsigned char* salt, int salt_len,
                         unsigned char* out_key) {
        if (!ptr) return 0;
        return ptr->derive_key_argon2id(password, salt, salt_len, out_key);
    }
}

class CryptoCore {

public:
    int rsa_encrypt_key_oaep(const unsigned char* aes_key_in, int key_len,
                             const char* rsa_pub_key_pem,
                             unsigned char* out_wrapped_key) {
        
        BIO* bio = BIO_new_mem_buf(rsa_pub_key_pem, -1);
        EVP_PKEY* pub_key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
        BIO_free(bio);
        
        if (!pub_key) return -1;

        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pub_key, NULL);
        if (!ctx) { EVP_PKEY_free(pub_key); return -1; }

        if (EVP_PKEY_encrypt_init(ctx) <= 0) {
            EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(pub_key); return -1;
        }

        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
             EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(pub_key); return -1;
        }

        size_t outlen;
        if (EVP_PKEY_encrypt(ctx, NULL, &outlen, aes_key_in, key_len) <= 0) {
            EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(pub_key); return -1;
        }
        
        if (EVP_PKEY_encrypt(ctx, out_wrapped_key, &outlen, aes_key_in, key_len) <= 0) {
             EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(pub_key); return -1;
        }

        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pub_key);
        
        return (int)outlen; // Mengembalikan panjang ciphertext RSA (misal 256 bytes untuk RSA-2048)
    }
};

extern "C" {
    int Crypto_RSA_Wrap(CryptoCore* ptr,
                        const unsigned char* aes_key,
                        const char* pub_key_pem,
                        unsigned char* out_buffer) {
        if (!ptr) return -1;
        return ptr->rsa_encrypt_key_oaep(aes_key, 32, pub_key_pem, out_buffer);
    }
}