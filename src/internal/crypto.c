#include "crypto.h"
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/kdf.h>
#include <openssl/bio.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define SALT_SIZE 16
#define PBKDF2_ITERATIONS 600000
#define AES_KEY_SIZE 32
#define AES_IV_SIZE 12
#define AES_TAG_SIZE 16

// Helper to log detailed OpenSSL errors for better debugging.
static void log_openssl_errors(const char* message) {
    fprintf(stderr, "CRYPTO_ERROR: %s\n", message);
    ERR_print_errors_fp(stderr);
}

crypto_status_t decrypt_secret_file(
    const unsigned char* data,
    size_t data_len,
    const char* password,
    unsigned char** plaintext_ptr,
    size_t* out_len
) {
    *plaintext_ptr = NULL;
    *out_len = 0;
    
    // We expect at least Salt + IV + Tag, ciphertext can be 0 length.
    if (data_len < SALT_SIZE + AES_IV_SIZE + AES_TAG_SIZE) {
        return CRYPTO_ERR_INPUT_TOO_SHORT;
    }

    // --- Parsing the [salt][iv][ciphertext][tag] structure ---
    const unsigned char* salt = data;
    const unsigned char* iv = data + SALT_SIZE;
    const unsigned char* ciphertext = data + SALT_SIZE + AES_IV_SIZE;
    size_t ciphertext_len = data_len - SALT_SIZE - AES_IV_SIZE - AES_TAG_SIZE;
    const unsigned char* tag = data + data_len - AES_TAG_SIZE;

    unsigned char key[AES_KEY_SIZE];
    if (PKCS5_PBKDF2_HMAC(password, strlen(password), salt, SALT_SIZE, PBKDF2_ITERATIONS, EVP_sha256(), AES_KEY_SIZE, key) != 1) {
        log_openssl_errors("PKCS5_PBKDF2_HMAC failed");
        return CRYPTO_ERR_KDF_FAILED;
    }

    // --- Using a robust cleanup pattern for OpenSSL context and buffers ---
    EVP_CIPHER_CTX* ctx = NULL;
    unsigned char* plaintext = NULL;
    crypto_status_t status = CRYPTO_SUCCESS; // Assume success initially
    int len = 0;
    int plaintext_len_int = 0;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        status = CRYPTO_ERR_MALLOC_FAILED;
        goto cleanup;
    }

    // 1. Initialize for AES-256-GCM
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        status = CRYPTO_ERR_DECRYPT_INIT_FAILED;
        goto cleanup;
    }
    
    // 2. Disable padding (mandatory for GCM)
    if (EVP_CIPHER_CTX_set_padding(ctx, 0) != 1) {
        status = CRYPTO_ERR_DECRYPT_INIT_FAILED;
        goto cleanup;
    }

    // 3. Set IV length
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_IV_SIZE, NULL) != 1) {
        status = CRYPTO_ERR_DECRYPT_INIT_FAILED;
        goto cleanup;
    }

    // 4. Provide key and IV
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        status = CRYPTO_ERR_DECRYPT_INIT_FAILED;
        goto cleanup;
    }

    // 5. Allocate memory for plaintext (same size as ciphertext for GCM)
    plaintext = malloc(ciphertext_len > 0 ? ciphertext_len + 1 : 1); // +1 for null terminator
    if (!plaintext) {
        status = CRYPTO_ERR_MALLOC_FAILED;
        goto cleanup;
    }

    // 6. Decrypt the main ciphertext body
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        log_openssl_errors("EVP_DecryptUpdate failed");
        status = CRYPTO_ERR_DECRYPT_UPDATE_FAILED;
        goto cleanup;
    }
    plaintext_len_int = len;

    // 7. Set the expected authentication tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_TAG_SIZE, (void*)tag) != 1) {
        log_openssl_errors("EVP_CIPHER_CTX_ctrl (SET_TAG) failed");
        status = CRYPTO_ERR_SET_TAG_FAILED;
        goto cleanup;
    }

    // 8. Finalize decryption. This performs the tag verification.
    // It will fail if the tag does not match.
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) <= 0) {
        log_openssl_errors("EVP_DecryptFinal_ex failed. Tag verification likely failed.");
        status = CRYPTO_ERR_TAG_VERIFY_FAILED;
        goto cleanup;
    }
    
    // On success, update length and output pointers
    plaintext_len_int += len;
    plaintext[plaintext_len_int] = '\0'; // Ensure null termination
    *out_len = plaintext_len_int;
    *plaintext_ptr = plaintext;
    plaintext = NULL; // Ownership is transferred to the caller, so prevent it from being freed by cleanup.

cleanup:
    // This block will execute on any error or at the end of the function.
    free(plaintext); // Will be NULL on success, so this is safe.
    if (ctx) EVP_CIPHER_CTX_free(ctx);

    // Securely wipe the derived key from memory
    OPENSSL_cleanse(key, sizeof(key));

    return status;
}


EVP_PKEY* parse_pem_private_key(const char* pem_data, size_t pem_len) {
    BIO* bio = BIO_new_mem_buf(pem_data, (int)pem_len);
    if (!bio) return NULL;
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return pkey;
}

EVP_PKEY* parse_pem_public_key(const char* pem_data, size_t pem_len) {
    BIO* bio = BIO_new_mem_buf(pem_data, (int)pem_len);
    if (!bio) return NULL;
    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return pkey;
}

char* base64_encode(const unsigned char* data, size_t input_length) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, data, input_length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    char* output = (char*)malloc(bufferPtr->length + 1);
    if(!output) { BIO_free_all(bio); return NULL; }
    memcpy(output, bufferPtr->data, bufferPtr->length);
    output[bufferPtr->length] = '\0';
    BIO_free_all(bio);
    return output;
}

unsigned char* base64_decode(const char* data, size_t* output_length) {
    BIO *bio, *b64;
    int data_len = (int)strlen(data); // Cast to int for BIO_new_mem_buf
    unsigned char* buffer = (unsigned char*)malloc(data_len);
    if(!buffer) return NULL;
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf((void*)data, data_len);
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    *output_length = BIO_read(bio, buffer, data_len);
    BIO_free_all(bio);
    return buffer;
}

char* sign_data_sha256_rsa(EVP_PKEY* private_key, const unsigned char* data, size_t data_len) {
    EVP_MD_CTX* md_ctx = NULL;
    char* b64_sig = NULL;
    unsigned char* sig = NULL;
    size_t sig_len;
    md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) goto cleanup;
    if (EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, private_key) <= 0) goto cleanup;
    if (EVP_DigestSignUpdate(md_ctx, data, data_len) <= 0) goto cleanup;
    if (EVP_DigestSignFinal(md_ctx, NULL, &sig_len) <= 0) goto cleanup;
    sig = malloc(sig_len);
    if (sig == NULL) goto cleanup;
    if (EVP_DigestSignFinal(md_ctx, sig, &sig_len) <= 0) goto cleanup;
    b64_sig = base64_encode(sig, sig_len);
cleanup:
    free(sig);
    if(md_ctx) EVP_MD_CTX_free(md_ctx);
    return b64_sig;
}

bool verify_signature_sha256_rsa(EVP_PKEY* public_key, const unsigned char* data, size_t data_len, const char* b64_signature) {
    EVP_MD_CTX* md_ctx = NULL;
    unsigned char* sig = NULL;
    size_t sig_len;
    bool result = false;
    sig = base64_decode(b64_signature, &sig_len);
    if (!sig) return false;
    md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) goto cleanup;
    if (EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, public_key) <= 0) goto cleanup;
    if (EVP_DigestVerifyUpdate(md_ctx, data, data_len) <= 0) goto cleanup;
    if (EVP_DigestVerifyFinal(md_ctx, sig, sig_len) == 1) {
        result = true;
    }
cleanup:
    free(sig);
    if(md_ctx) EVP_MD_CTX_free(md_ctx);
    return result;
}