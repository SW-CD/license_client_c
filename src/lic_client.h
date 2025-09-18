#ifndef LIC_CLIENT_H
#define LIC_CLIENT_H

#include <stdbool.h>
#include <stdint.h>

/* =============================================================================
 * Platform-specific definitions for exporting/importing from a shared library
 * =============================================================================
 */
#ifdef _WIN32
  #ifdef LIC_CLIENT_STATIC_LIB
    #define LIC_CLIENT_API
  #else
    #ifdef LIC_CLIENT_EXPORTS
      #define LIC_CLIENT_API __declspec(dllexport)
    #else
      #define LIC_CLIENT_API __declspec(dllimport)
    #endif
  #endif
#else
  #define LIC_CLIENT_API __attribute__((visibility("default")))
#endif

/* =============================================================================
 * Public Data Structures and Enums
 * =============================================================================
 */

/**
 * @brief An opaque handle to the client datastore.
 * Its contents are internal to the library.
 */
typedef struct lic_client_datastore lic_client_datastore;

/**
 * @brief Status codes returned by the library functions.
 * These are ABI-compatible with the Rust client library.
 */
typedef enum {
    LIC_SUCCESS = 0,
    LIC_ERROR_GENERIC = -1,
    LIC_ERROR_FILE_NOT_FOUND = -2,
    LIC_ERROR_BAD_PASSWORD = -3,
    LIC_ERROR_INVALID_SECRET_FILE = -4,
    LIC_ERROR_NETWORK = -5,
    // -6 is reserved for the old SERVER_RESPONSE error
    LIC_ERROR_SIGNATURE_VERIFICATION = -7,
    LIC_ERROR_NOT_AUTHENTICATED = -8,
    LIC_ERROR_LICENSES_IN_USE = -9,
    LIC_ERROR_JSON_PARSE = -10,
    LIC_ERROR_JSON_STRUCTURE = -11,
    LIC_ERROR_KEY_PARSE = -12,
    LIC_ERROR_FORBIDDEN = -13,
    LIC_ERROR_RATE_LIMITED = -14,
    LIC_ERROR_INTERNAL_SERVER = -15,
    LIC_ERROR_SERVICE_UNAVAILABLE = -16,
    LIC_ERROR_UNHANDLED_RESPONSE = -17,

} lic_client_status;


/* =============================================================================
 * Public API Functions
 * =============================================================================
 */

/**
 * @brief Parses a client secret file (.json or .enc.json).
 * On success, allocates memory for the datastore. The caller MUST call
 * lic_client_free_datastore() on the resulting pointer.
 */
LIC_CLIENT_API lic_client_status lic_client_parse_secret_file(const char* file_path, const char* password, lic_client_datastore** datastore_ptr);

/**
 * @brief Sets the policy for TLS certificate verification.
 * FOR DEVELOPMENT ONLY: Setting allow to true disables server certificate validation.
 */
LIC_CLIENT_API void lic_client_set_insecure_tls(lic_client_datastore* store, bool allow);

/**
 * @brief Sets the network timeout for all server requests.
 * @param store The datastore object.
 * @param milliseconds The timeout value in milliseconds. A value of 0 means
 * the request will not time out. Default is 15000 (15s).
 */
LIC_CLIENT_API void lic_client_set_timeout(lic_client_datastore* store, int64_t milliseconds);

/**
 * @brief Performs mutual authentication with the license server.
 * On success, updates the session_token and custom_content within the datastore.
 */
LIC_CLIENT_API lic_client_status lic_client_authenticate(lic_client_datastore* store);

/**
 * @brief Sends a keepalive message to the server to maintain the session.
 */
LIC_CLIENT_API lic_client_status lic_client_keepalive(lic_client_datastore* store);

/**
 * @brief Sends a release message to the server to terminate the session.
 * This should be called on graceful application shutdown.
 */
LIC_CLIENT_API lic_client_status lic_client_release(lic_client_datastore* store);

/**
 * @brief Frees all memory associated with a datastore object.
 */
LIC_CLIENT_API void lic_client_free_datastore(lic_client_datastore* store);

/**
 * @brief Converts a status code into a human-readable string.
 */
LIC_CLIENT_API const char* lic_client_status_to_string(lic_client_status status);


/* =============================================================================
 * Public Data Accessor Functions (for Opaque Struct)
 * =============================================================================
 */

/** @brief Gets the Client ID from the datastore. */
LIC_CLIENT_API const char* lic_client_get_client_id(const lic_client_datastore* store);

/** @brief Gets the Server URL from the datastore. */
LIC_CLIENT_API const char* lic_client_get_server_url(const lic_client_datastore* store);

/** @brief Gets the current session token from the datastore (can be NULL). */
LIC_CLIENT_API const char* lic_client_get_session_token(const lic_client_datastore* store);

/** @brief Gets the custom content from the datastore (can be NULL). */
LIC_CLIENT_API const char* lic_client_get_custom_content(const lic_client_datastore* store);


#endif // LIC_CLIENT_H