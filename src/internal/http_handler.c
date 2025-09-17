#include "http_handler.h"
#include "lic_client_internal.h"
#include "crypto.h"
#include "http.h"
#include "json_helpers.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <jansson.h>

// Forward declarations for static helper functions
static json_t* build_request_json(lic_client_datastore* store, const char* msg_type, const char* nonce);
static lic_client_status process_successful_response(lic_client_datastore* store, const char* resp_body, const char* b64_nonce, bool is_auth);
static lic_client_status handle_error_response(long http_status, const char* resp_body);

lic_client_status handle_auth_or_keepalive_request(lic_client_datastore* store, bool is_auth) {
    if (!store) return LIC_ERROR_GENERIC;

    unsigned char client_nonce[32];
    if (RAND_bytes(client_nonce, sizeof(client_nonce)) != 1) return LIC_ERROR_GENERIC;
    
    char* b64_nonce = base64_encode(client_nonce, sizeof(client_nonce));
    if (!b64_nonce) return LIC_ERROR_GENERIC;

    const char* msg_type = is_auth ? "Authentication" : "Keepalive";
    json_t* req_json = build_request_json(store, msg_type, b64_nonce);
    if (!req_json) {
        free(b64_nonce);
        return LIC_ERROR_GENERIC;
    }

    char* req_body = json_dumps(req_json, JSON_COMPACT);
    json_decref(req_json);
    
    char auth_url[512];
    snprintf(auth_url, sizeof(auth_url), "%s/auth", store->server_url);
    
    long http_status = 0;
    char* resp_body = http_post_json(auth_url, req_body, store->allow_insecure_tls, store->timeout_ms, &http_status);
    free(req_body);

    if (!resp_body) {
        free(b64_nonce);
        return LIC_ERROR_NETWORK;
    }

    lic_client_status status = LIC_SUCCESS;
    if (http_status == 200) {
        status = process_successful_response(store, resp_body, b64_nonce, is_auth);
    } else {
        status = handle_error_response(http_status, resp_body);
    }

    free(resp_body);
    free(b64_nonce);
    return status;
}

lic_client_status handle_release_request(lic_client_datastore* store) {
    if (!store) return LIC_ERROR_GENERIC;
    // If there's no token, there's nothing to release. Return success.
    if (!store->session_token) return LIC_SUCCESS;

    json_t* req_json = json_object();
    json_object_set_new(req_json, "msg", json_string("Release"));
    json_object_set_new(req_json, "client_id", json_string(store->client_id));
    json_object_set_new(req_json, "token", json_string(store->session_token));

    char* req_body = json_dumps(req_json, JSON_COMPACT);
    json_decref(req_json);
    
    char auth_url[512];
    snprintf(auth_url, sizeof(auth_url), "%s/auth", store->server_url);

    long http_status = 0;
    char* resp_body = http_post_json(auth_url, req_body, store->allow_insecure_tls, store->timeout_ms, &http_status);
    free(req_body);

    if (!resp_body) return LIC_ERROR_NETWORK;

    // For release, 200 and 404 are success. Other errors are handled.
    if (http_status == 200 || http_status == 404) {
        free(resp_body);
        free(store->session_token);
        store->session_token = NULL;
        free(store->custom_content);
        store->custom_content = NULL;
        free(store->content_signature);
        store->content_signature = NULL;
        return LIC_SUCCESS;
    }
    
    lic_client_status status = handle_error_response(http_status, resp_body);
    free(resp_body);
    return status;
}

// --- Static Helper Function Implementations ---

static json_t* build_request_json(lic_client_datastore* store, const char* msg_type, const char* nonce) {
    json_t* req_json = json_object();
    json_object_set_new(req_json, "msg", json_string(msg_type));
    json_object_set_new(req_json, "client_id", json_string(store->client_id));
    json_object_set_new(req_json, "nonce", json_string(nonce));

    if (strcmp(msg_type, "Authentication") == 0) {
        char to_sign[512];
        snprintf(to_sign, sizeof(to_sign), "%s:%s", nonce, store->client_id);
        
        char* b64_signature = sign_data_sha256_rsa(store->client_private_key, (unsigned char*)to_sign, strlen(to_sign));
        if (!b64_signature) { json_decref(req_json); return NULL; }
        
        json_object_set_new(req_json, "client_signature", json_string(b64_signature));
        free(b64_signature);
    } else { // Keepalive
        json_object_set_new(req_json, "token", json_string(store->session_token));
    }
    return req_json;
}

static lic_client_status process_successful_response(lic_client_datastore* store, const char* resp_body, const char* b64_nonce, bool is_auth) {
    json_error_t error;
    json_t* resp_json = json_loads(resp_body, 0, &error);
    if (!resp_json) return LIC_ERROR_JSON_PARSE;

    lic_client_status status = LIC_SUCCESS;
    const char* error_msg = json_get_string(resp_json, "msg");
    if (error_msg && strcmp(error_msg, "OK") != 0) {
        status = LIC_ERROR_UNHANDLED_RESPONSE;
        goto cleanup;
    }

    const char* b64_nonce_signed = json_get_string(resp_json, "nonce_signed");
    if (!b64_nonce_signed || !verify_signature_sha256_rsa(store->server_public_key, (const unsigned char*)b64_nonce, strlen(b64_nonce), b64_nonce_signed)) {
        status = LIC_ERROR_SIGNATURE_VERIFICATION;
        goto cleanup;
    }

    if (is_auth) {
        const char* token_str = json_get_string(resp_json, "token");
        if (!token_str) { status = LIC_ERROR_JSON_STRUCTURE; goto cleanup; }
        
        free(store->session_token);
        store->session_token = strdup(token_str);

        const char* content_str = json_get_string(resp_json, "custom_content");
        const char* content_sig_str = json_get_string(resp_json, "content_signature");

        if (content_str && !content_sig_str) { status = LIC_ERROR_SIGNATURE_VERIFICATION; goto cleanup; }
        if (content_str && content_sig_str) {
            if (!verify_signature_sha256_rsa(store->server_public_key, (const unsigned char*)content_str, strlen(content_str), content_sig_str)) {
                status = LIC_ERROR_SIGNATURE_VERIFICATION;
                goto cleanup;
            }
            free(store->custom_content);
            store->custom_content = strdup(content_str);
            free(store->content_signature);
            store->content_signature = strdup(content_sig_str);
        }
    }

cleanup:
    json_decref(resp_json);
    return status;
}

static lic_client_status handle_error_response(long http_status, const char* resp_body) {
    switch (http_status) {
        case 429: {
            json_error_t error;
            json_t* resp_json = json_loads(resp_body, 0, &error);
            if (resp_json) {
                const char* msg = json_get_string(resp_json, "error");
                if (msg && strstr(msg, "All licenses in use")) {
                    json_decref(resp_json);
                    return LIC_ERROR_LICENSES_IN_USE;
                }
                json_decref(resp_json);
            }
            return LIC_ERROR_RATE_LIMITED;
        }
        case 403: return LIC_ERROR_FORBIDDEN;
        case 500: return LIC_ERROR_INTERNAL_SERVER;
        case 503: return LIC_ERROR_SERVICE_UNAVAILABLE;
        default: return LIC_ERROR_UNHANDLED_RESPONSE;
    }
}