#ifndef HTTP_INTERNAL_H
#define HTTP_INTERNAL_H

#include <stdbool.h> // Include for the bool type
#include <stdint.h> // Include for int64_t

/**
 * @brief Performs an HTTP POST request with a JSON payload.
 *
 * This function handles the creation of a libcurl easy handle, setting
 * the necessary options for a POST request, sending the data, and capturing
 * the response.
 *
 * @param url The full URL to send the POST request to.
 * @param post_data A null-terminated string containing the JSON payload.
 * @param allow_insecure If true, TLS certificate validation will be disabled.
 * WARNING: This should only be used for local development.
 * @param http_status_code A pointer to a long integer where the HTTP response
 * status code will be stored (e.g., 200, 403, 500).
 * @return A newly allocated, null-terminated string containing the response
 * body on success, or NULL on failure (e.g., network error). The caller is
 * responsible for freeing this string.
 */
char* http_post_json(const char* url, const char* post_data, bool allow_insecure, int64_t timeout_ms, long* http_status_code);

#endif // HTTP_INTERNAL_H