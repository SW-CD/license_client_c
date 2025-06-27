#ifndef CRYPTO_INTERNAL_H
#define CRYPTO_INTERNAL_H

#include <openssl/evp.h>
#include <stdbool.h>
#include <stddef.h>

typedef enum {
    CRYPTO_SUCCESS = 0,
    CRYPTO_ERR_MALLOC_FAILED = -1,
    CRYPTO_ERR_INPUT_TOO_SHORT = -2,
    CRYPTO_ERR_KDF_FAILED = -3,
    CRYPTO_ERR_DECRYPT_INIT_FAILED = -4,
    CRYPTO_ERR_DECRYPT_UPDATE_FAILED = -5,
    CRYPTO_ERR_SET_TAG_FAILED = -6,
    CRYPTO_ERR_TAG_VERIFY_FAILED = -7
} crypto_status_t;

/**
 * @brief Decrypts data using the PBE scheme (PBKDF2 + AES-256-GCM).
 *
 * This function is completely rewritten for robust error handling. On success,
 * it allocates memory for the plaintext and places it in plaintext_ptr.
 * The caller MUST free this memory.
 *
 * @param data The raw encrypted byte buffer.
 * @param data_len The length of the data buffer.
 * @param password The password for decryption.
 * @param plaintext_ptr A pointer to an unsigned char pointer, which will be
 * populated by this function on success.
 * @param out_len A pointer to a size_t to store the length of the
 * decrypted plaintext.
 * @return A crypto_status_t code. CRYPTO_SUCCESS on success.
 */
crypto_status_t decrypt_secret_file(
    const unsigned char* data,
    size_t data_len,
    const char* password,
    unsigned char** plaintext_ptr,
    size_t* out_len
);

/**
 * @brief Parses a PEM-encoded RSA private key.
 * @param pem_data A buffer containing the PEM key string.
 * @param pem_len The length of the buffer.
 * @return A pointer to an EVP_PKEY object on success, or NULL on failure.
 * The caller is responsible for freeing this object with EVP_PKEY_free().
 */
EVP_PKEY* parse_pem_private_key(const char* pem_data, size_t pem_len);

/**
 * @brief Parses a PEM-encoded RSA public key (PKIX format).
 * @param pem_data A buffer containing the PEM key string.
 * @param pem_len The length of the buffer.
 * @return A pointer to an EVP_PKEY object on success, or NULL on failure.
 * The caller is responsible for freeing this object with EVP_PKEY_free().
 */
EVP_PKEY* parse_pem_public_key(const char* pem_data, size_t pem_len);

/**
 * @brief Signs a block of data using SHA-256 with RSA.
 * @param private_key The EVP_PKEY object containing the private key.
 * @param data The data to sign.
 * @param data_len The length of the data.
 * @return A newly allocated, null-terminated, Base64-encoded signature string
 * on success, or NULL on failure. The caller must free this string.
 */
char* sign_data_sha256_rsa(EVP_PKEY* private_key, const unsigned char* data, size_t data_len);

/**
 * @brief Verifies a SHA-256 with RSA signature.
 * @param public_key The EVP_PKEY object containing the public key.
 * @param data The original data that was signed.
 * @param data_len The length of the original data.
 * @param b64_signature The Base64-encoded signature to verify.
 * @return true if the signature is valid, false otherwise.
 */
bool verify_signature_sha256_rsa(EVP_PKEY* public_key, const unsigned char* data, size_t data_len, const char* b64_signature);

/**
 * @brief Base64-encodes a block of data.
 * @param data The data to encode.
 * @param input_length The length of the data.
 * @return A newly allocated, null-terminated, Base64-encoded string. The
 * caller must free this string. Returns NULL on failure.
 */
char* base64_encode(const unsigned char* data, size_t input_length);

/**
 * @brief Base64-decodes a string.
 * @param data The Base64-encoded string.
 * @param output_length A pointer to store the length of the decoded data.
 * @return A newly allocated buffer with the decoded data. The caller must
 * free this buffer. Returns NULL on failure.
 */
unsigned char* base64_decode(const char* data, size_t* output_length);

#endif // CRYPTO_INTERNAL_H
