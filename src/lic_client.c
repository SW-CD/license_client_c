#include "lic_client.h"
#include "internal/lic_client_internal.h"
#include "internal/http_handler.h"
#include "internal/crypto.h"
#include "internal/json_helpers.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

// --- Public API Implementation ---

LIC_CLIENT_API void lic_client_free_datastore(lic_client_datastore* store) {
    if (!store) return;
    free(store->client_id);
    free(store->server_url);
    free(store->session_token);
    free(store->custom_content);
    free(store->content_signature);
    if(store->server_public_key) EVP_PKEY_free(store->server_public_key);
    if(store->client_private_key) EVP_PKEY_free(store->client_private_key);
    free(store);
}

LIC_CLIENT_API lic_client_status lic_client_parse_secret_file(const char* file_path, const char* password, lic_client_datastore** datastore_ptr) {
    if (datastore_ptr == NULL) return LIC_ERROR_GENERIC;
    *datastore_ptr = NULL;

    FILE* fp = fopen(file_path, "rb");
    if (!fp) return LIC_ERROR_FILE_NOT_FOUND;

    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (file_size <= 0) { fclose(fp); return LIC_ERROR_INVALID_SECRET_FILE; }

    unsigned char* file_content = malloc(file_size);
    if (!file_content) { fclose(fp); return LIC_ERROR_GENERIC; }

    if (fread(file_content, 1, file_size, fp) != (size_t)file_size) {
        free(file_content);
        fclose(fp);
        return LIC_ERROR_INVALID_SECRET_FILE;
    }
    fclose(fp);

    unsigned char* plaintext_json_bytes = NULL;
    size_t plaintext_len = 0;

    const char* suffix = ".enc.json";
    size_t path_len = strlen(file_path);
    size_t suffix_len = strlen(suffix);
    bool is_encrypted = (path_len >= suffix_len) && (strcmp(file_path + path_len - suffix_len, suffix) == 0);

    if (is_encrypted) {
        if (!password || strlen(password) == 0) { free(file_content); return LIC_ERROR_BAD_PASSWORD; }

        if (decrypt_secret_file(file_content, file_size, password, &plaintext_json_bytes, &plaintext_len) != CRYPTO_SUCCESS) {
            free(file_content);
            return LIC_ERROR_BAD_PASSWORD;
        }
        free(file_content);
    } else {
        plaintext_json_bytes = file_content;
    }

    json_error_t error;
    json_t* root = json_loadb((const char*)plaintext_json_bytes, strlen((char*)plaintext_json_bytes), 0, &error);
    free(plaintext_json_bytes);
    if (!root) return LIC_ERROR_JSON_PARSE;

    const char* client_id_str = json_get_string(root, "client_id");
    const char* server_url_str = json_get_string(root, "server_url");
    const char* server_pub_key_pem = json_get_string(root, "server_public_key");
    const char* client_priv_key_pem = json_get_string(root, "client_private_key");

    if (!client_id_str || !server_url_str || !server_pub_key_pem || !client_priv_key_pem) {
        json_decref(root);
        return LIC_ERROR_JSON_STRUCTURE;
    }

    lic_client_datastore* store = calloc(1, sizeof(lic_client_datastore));
    if(!store) { json_decref(root); return LIC_ERROR_GENERIC; }

    store->client_id = strdup(client_id_str);
    store->server_url = strdup(server_url_str);
    store->server_public_key = parse_pem_public_key(server_pub_key_pem, strlen(server_pub_key_pem));
    store->client_private_key = parse_pem_private_key(client_priv_key_pem, strlen(client_priv_key_pem));
    json_decref(root);

    if (!store->client_id || !store->server_url || !store->server_public_key || !store->client_private_key) {
        lic_client_free_datastore(store);
        return LIC_ERROR_KEY_PARSE;
    }

    *datastore_ptr = store;
    return LIC_SUCCESS;
}

LIC_CLIENT_API void lic_client_set_insecure_tls(lic_client_datastore* store, bool allow) {
    if (store) store->allow_insecure_tls = allow;
}

LIC_CLIENT_API lic_client_status lic_client_authenticate(lic_client_datastore* store) {
    if (!store) return LIC_ERROR_GENERIC;
    return handle_auth_or_keepalive_request(store, true);
}

LIC_CLIENT_API lic_client_status lic_client_keepalive(lic_client_datastore* store) {
    if (!store) return LIC_ERROR_GENERIC;
    if (!store->session_token) return LIC_ERROR_NOT_AUTHENTICATED;
    return handle_auth_or_keepalive_request(store, false);
}

LIC_CLIENT_API lic_client_status lic_client_release(lic_client_datastore* store) {
    if (!store) return LIC_ERROR_GENERIC;
    return handle_release_request(store);
}

LIC_CLIENT_API const char* lic_client_status_to_string(lic_client_status status) {
    switch (status) {
        case LIC_SUCCESS: return "LIC_SUCCESS";
        case LIC_ERROR_GENERIC: return "LIC_ERROR_GENERIC";
        case LIC_ERROR_FILE_NOT_FOUND: return "LIC_ERROR_FILE_NOT_FOUND";
        case LIC_ERROR_BAD_PASSWORD: return "LIC_ERROR_BAD_PASSWORD";
        case LIC_ERROR_INVALID_SECRET_FILE: return "LIC_ERROR_INVALID_SECRET_FILE";
        case LIC_ERROR_JSON_PARSE: return "LIC_ERROR_JSON_PARSE";
        case LIC_ERROR_JSON_STRUCTURE: return "LIC_ERROR_JSON_STRUCTURE";
        case LIC_ERROR_KEY_PARSE: return "LIC_ERROR_KEY_PARSE";
        case LIC_ERROR_NETWORK: return "LIC_ERROR_NETWORK";
        case LIC_ERROR_SIGNATURE_VERIFICATION: return "LIC_ERROR_SIGNATURE_VERIFICATION";
        case LIC_ERROR_NOT_AUTHENTICATED: return "LIC_ERROR_NOT_AUTHENTICATED";
        case LIC_ERROR_LICENSES_IN_USE: return "LIC_ERROR_LICENSES_IN_USE";
        case LIC_ERROR_FORBIDDEN: return "LIC_ERROR_FORBIDDEN";
        case LIC_ERROR_RATE_LIMITED: return "LIC_ERROR_RATE_LIMITED";
        case LIC_ERROR_INTERNAL_SERVER: return "LIC_ERROR_INTERNAL_SERVER";
        case LIC_ERROR_SERVICE_UNAVAILABLE: return "LIC_ERROR_SERVICE_UNAVAILABLE";
        case LIC_ERROR_UNHANDLED_RESPONSE: return "LIC_ERROR_UNHANDLED_RESPONSE";
        default: return "UNKNOWN_STATUS";
    }
}

// --- Public Data Accessor Functions ---

LIC_CLIENT_API const char* lic_client_get_client_id(const lic_client_datastore* store) {
    return store ? store->client_id : NULL;
}
LIC_CLIENT_API const char* lic_client_get_server_url(const lic_client_datastore* store) {
    return store ? store->server_url : NULL;
}
LIC_CLIENT_API const char* lic_client_get_session_token(const lic_client_datastore* store) {
    return store ? store->session_token : NULL;
}
LIC_CLIENT_API const char* lic_client_get_custom_content(const lic_client_datastore* store) {
    return store ? store->custom_content : NULL;
}