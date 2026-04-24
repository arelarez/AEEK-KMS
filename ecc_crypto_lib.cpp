#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/err.h>
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
        EVP_KDF_free(kdf);
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
        *p++ = OSSL_PARAM_construct_uint32("lanes", &parallelism);
        *p++ = OSSL_PARAM_construct_end();

        int ret = EVP_KDF_derive(kctx, out_key, 32, params);

        EVP_KDF_CTX_free(kctx);
        
        if (ret <= 0) return 0;
        return 1;
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
    int generate_ecc_keypair(unsigned char* out_pub, unsigned char* out_priv) {
        EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
        EVP_PKEY_keygen_init(pctx);
        
        EVP_PKEY *pkey = NULL;
        EVP_PKEY_keygen(pctx, &pkey);
        EVP_PKEY_CTX_free(pctx);

        size_t len_pub = 32;
        size_t len_priv = 32;

        EVP_PKEY_get_raw_public_key(pkey, out_pub, &len_pub);
        EVP_PKEY_get_raw_private_key(pkey, out_priv, &len_priv);
        
        EVP_PKEY_free(pkey);
        return 1;
    }

    int compute_ecdh_secret(const unsigned char* my_priv_raw, 
                            const unsigned char* peer_pub_raw,
                            unsigned char* out_shared_secret) {
        
        EVP_PKEY *my_key = EVP_PKEY_new_raw_private_key(
            EVP_PKEY_X25519, NULL, my_priv_raw, 32);

        EVP_PKEY *peer_key = EVP_PKEY_new_raw_public_key(
            EVP_PKEY_X25519, NULL, peer_pub_raw, 32);

        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(my_key, NULL);
        EVP_PKEY_derive_init(ctx);
        EVP_PKEY_derive_set_peer(ctx, peer_key);

        size_t secret_len;
        EVP_PKEY_derive(ctx, NULL, &secret_len);
        
        EVP_PKEY_derive(ctx, out_shared_secret, &secret_len);

        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(my_key);
        EVP_PKEY_free(peer_key);
        
        return 1;
    }
};

extern "C" {
    int Crypto_Generate_ECC(CryptoCore* ptr, unsigned char* pub, unsigned char* priv) {
        return ptr->generate_ecc_keypair(pub, priv);
    }

    int Crypto_Compute_ECDH(CryptoCore* ptr, 
                            const unsigned char* my_priv, 
                            const unsigned char* peer_pub, 
                            unsigned char* out_secret) {
        return ptr->compute_ecdh_secret(my_priv, peer_pub, out_secret);
    }
}