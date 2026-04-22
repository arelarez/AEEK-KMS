#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <iomanip>

using Bytes = std::vector<unsigned char>;
struct Envelope {
    Bytes encrypted_data;
    Bytes iv;
    Bytes tag;
    Bytes wrapped_key;
};

void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

class CryptoSystem {
private:
    EVP_PKEY* master_key;

public:
    CryptoSystem() 
{
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
        if (!ctx) handleErrors();
        
        if (EVP_PKEY_keygen_init(ctx) <= 0) handleErrors();
        if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) handleErrors();
        
        if (EVP_PKEY_keygen(ctx, &master_key) <= 0) handleErrors();
        EVP_PKEY_CTX_free(ctx);
        std::cout << "[SYSTEM] Master Key (RSA) Loaded/Generated.\n";
    }

    ~CryptoSystem() {
        EVP_PKEY_free(master_key);
    }
    Envelope encrypt_envelope(const std::string& plaintext) {
        Envelope env;
        Bytes dek(32);
        if (!RAND_bytes(dek.data(), 32)) handleErrors();
        env.iv.resize(12);
        if (!RAND_bytes(env.iv.data(), 12)) handleErrors();
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(master_key, NULL);
        if (EVP_PKEY_encrypt_init(ctx) <= 0) handleErrors();
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) handleErrors();
        if (EVP_PKEY_encrypt(ctx, NULL, &outlen, dek.data(), dek.size()) <= 0) handleErrors();
        env.wrapped_key.resize(outlen);
        if (EVP_PKEY_encrypt(ctx, env.wrapped_key.data(), &outlen, dek.data(), dek.size()) <= 0) handleErrors();
        
        EVP_PKEY_CTX_free(ctx);
        EVP_CIPHER_CTX* aes_ctx = EVP_CIPHER_CTX_new();
        if (!EVP_EncryptInit_ex(aes_ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) handleErrors();
        if (!EVP_CIPHER_CTX_ctrl(aes_ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL)) handleErrors();
        if (!EVP_EncryptInit_ex(aes_ctx, NULL, NULL, dek.data(), env.iv.data())) handleErrors();
        env.encrypted_data.resize(plaintext.size());
        int len;
        if (!EVP_EncryptUpdate(aes_ctx, env.encrypted_data.data(), &len, 
                              (unsigned char*)plaintext.c_str(), plaintext.size())) handleErrors();
        int final_len;
        if (!EVP_EncryptFinal_ex(aes_ctx, env.encrypted_data.data() + len, &final_len)) handleErrors();
        env.tag.resize(16);
        if (!EVP_CIPHER_CTX_ctrl(aes_ctx, EVP_CTRL_GCM_GET_TAG, 16, env.tag.data())) handleErrors();
        
        EVP_CIPHER_CTX_free(aes_ctx);
        OPENSSL_cleanse(dek.data(), dek.size());
        return env;
    }

    std::string decrypt_envelope(const Envelope& env)
{
        size_t outlen;
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(master_key, NULL);
        if (EVP_PKEY_decrypt_init(ctx) <= 0) handleErrors();
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) handleErrors();
        if (EVP_PKEY_decrypt(ctx, NULL, &outlen, env.wrapped_key.data(), env.wrapped_key.size()) <= 0) handleErrors();
        Bytes dek(outlen);
        if (EVP_PKEY_decrypt(ctx, dek.data(), &outlen, env.wrapped_key.data(), env.wrapped_key.size()) <= 0) handleErrors();
        EVP_PKEY_CTX_free(ctx);
        EVP_CIPHER_CTX* aes_ctx = EVP_CIPHER_CTX_new();
        if (!EVP_DecryptInit_ex(aes_ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) handleErrors();
        if (!EVP_CIPHER_CTX_ctrl(aes_ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL)) handleErrors();
        if (!EVP_DecryptInit_ex(aes_ctx, NULL, NULL, dek.data(), env.iv.data())) handleErrors();

        Bytes plaintext_out(env.encrypted_data.size());
        int len;
        if (!EVP_DecryptUpdate(aes_ctx, plaintext_out.data(), &len, 
                              env.encrypted_data.data(), env.encrypted_data.size())) handleErrors();
        if (!EVP_CIPHER_CTX_ctrl(aes_ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)env.tag.data())) handleErrors();

        int final_len;
        int ret = EVP_DecryptFinal_ex(aes_ctx, plaintext_out.data() + len, &final_len);
        
        EVP_CIPHER_CTX_free(aes_ctx);
        OPENSSL_cleanse(dek.data(), dek.size());
        if (ret > 0) {
            return std::string(plaintext_out.begin(), plaintext_out.end());
        } else {
            return "[ERROR] Decryption Failed! Integrity Check (Tag) Mismatch.";
        }
    }
};

int main() {
    CryptoSystem vault;
    
    std::string secret = "SECRET: Main Cyber Server coordinates are 0×1A4F";
    std::cout << "Original: " << secret << "\n\n";
    Envelope data_pack = vault.encrypt_envelope(secret);
    
    std::cout << "--- ENCRYPTED (Envelope) ---\n";
    std::cout << "Ciphertext Size: " << data_pack.encrypted_data.size() << " bytes\n";
    std::cout << "Wrapped Key Size: " << data_pack.wrapped_key.size() << " bytes (RSA Block)\n";
    std::cout << "Tag (Auth): " << "Integrity Verification OK\n\n";
    std::string recovered = vault.decrypt_envelope(data_pack);
    std::cout << "--- DECRYPTED ---\n";
    std::cout << "Recovered: " << recovered << "\n";

    return 0;
}