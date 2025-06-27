#ifndef LIC_CLIENT_INTERNAL_H
#define LIC_CLIENT_INTERNAL_H

#include "lic_client.h" // Include the public API for enums and the typedef
#include <stdbool.h>
#include <openssl/evp.h>

/**
 * @brief The internal, complete definition of the datastore.
 * This is kept private to the library's implementation files.
 */
struct lic_client_datastore {
    char* client_id;
    char* server_url;
    EVP_PKEY* server_public_key;
    EVP_PKEY* client_private_key;
    char* session_token;
    char* custom_content;
    char* content_signature;
    bool allow_insecure_tls;
};

#endif // LIC_CLIENT_INTERNAL_H