# C Client Library for Custom Licensing System

A lightweight, portable C client library for authenticating with the custom Go-based licensing server. This library handles secure parsing of client secret files, mutual authentication with the server, and full session lifecycle management, including keepalives and graceful release.

## Features

  * **Secure Credential Handling**: Parses both plain-text (`.json`) and password-encrypted (`.enc.json`) client secret files.
  * **Modern Cryptography**: Uses PBKDF2 with 600,000 iterations for key derivation and AES-256-GCM for authenticated encryption.
  * **Mutual Authentication**: Implements a challenge-response handshake where both the client and server prove their identity by signing a random nonce.
  * **Full Session Lifecycle**: Supports initial authentication, periodic session keepalives, and graceful session termination on the server via a `release` call.
  * **Robust API Design**: Features an opaque data handle (`lic_client_datastore`) to ensure safe state management and a clear, easy-to-use set of functions.

## Dependencies

To build this library, you will need the following dependencies installed:

  * **CMake** (version 3.10 or higher)
  * **A C Compiler** (GCC, Clang, etc.)
  * **OpenSSL** (libssl-dev)
  * **libcurl** (libcurl4-openssl-dev)
  * **Jansson** (libjansson-dev)
  * **PkgConfig**

## Building and Installing

The project uses CMake for building and installation. The process is standard on both Linux and Windows. The build system will produce both a shared library (`liblicclient.so` or `.dll`) and a static library (`liblicclient_static.a`).

### Building on Linux (Debian/Ubuntu)

1.  **Install Dependencies:**

    ```sh
    sudo apt-get update
    sudo apt-get install build-essential cmake libssl-dev libcurl4-openssl-dev libjansson-dev pkg-config
    ```

2.  **Configure and Build:**

    ```sh
    # From the root of the project directory
    mkdir build
    cd build
    cmake ..
    cmake --build .
    ```

### Building on Windows (with MSYS2/MinGW)

1.  **Install Dependencies:**

    ```sh
    pacman -Syu
    pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-cmake mingw-w64-x86_64-openssl mingw-w64-x86_64-curl mingw-w64-x86_64-jansson mingw-w64-x86_64-pkg-config
    ```

2.  **Configure and Build:**

    ```sh
    # From the root of the project directory
    mkdir build
    cd build
    cmake .. -G "MinGW Makefiles"
    cmake --build .
    ```

### Installation

After building, you can install the libraries, headers, and example executable to a system or local directory.

```sh
# From within the build directory
cmake --install . --prefix "C:/your/install/path"
```

### CMake Options

  * `-DBUILD_EXAMPLE=ON`: Builds the `example_client` executable located in `main.c`. Defaults to `ON`.

## API Reference

The public API is defined entirely in `src/lic_client.h`.

### Public Structures and Enums

#### `lic_client_status`

This enum represents all possible return codes from the library's functions. The new error codes provide more specific details about HTTP-level failures.

| Status Code                        | Description                                                                    |
| ---------------------------------- | ------------------------------------------------------------------------------ |
| `LIC_SUCCESS`                      | The operation completed successfully.                                          |
| `LIC_ERROR_GENERIC`                | A generic or unclassified error occurred (e.g., malloc failure).               |
| `LIC_ERROR_FILE_NOT_FOUND`         | The specified client secret file does not exist.                               |
| `LIC_ERROR_BAD_PASSWORD`           | The provided password for an encrypted secret file was incorrect.              |
| `LIC_ERROR_INVALID_SECRET_FILE`    | The secret file is empty or could not be read.                                 |
| `LIC_ERROR_NETWORK`                | A network-level error occurred (e.g., could not connect to host).              |
| `LIC_ERROR_SIGNATURE_VERIFICATION` | The server's signature for a nonce or content was invalid.                     |
| `LIC_ERROR_NOT_AUTHENTICATED`      | An operation requiring authentication was called before authenticating.        |
| `LIC_ERROR_LICENSES_IN_USE`        | The server reported that all available licenses are currently in use.          |
| `LIC_ERROR_JSON_PARSE`             | The decrypted or received content is not valid JSON.                           |
| `LIC_ERROR_JSON_STRUCTURE`         | The JSON is valid but is missing required fields (`client_id`, etc.).          |
| `LIC_ERROR_KEY_PARSE`              | A PEM-formatted key within the JSON is malformed.                              |
| `LIC_ERROR_FORBIDDEN`              | The server responded with an HTTP 403 Forbidden status.                        |
| `LIC_ERROR_RATE_LIMITED`           | The server responded with an HTTP 429 Rate Limited status.                     |
| `LIC_ERROR_INTERNAL_SERVER`        | The server responded with an HTTP 500 Internal Server Error.                   |
| `LIC_ERROR_SERVICE_UNAVAILABLE`    | The server responded with an HTTP 503 Service Unavailable.                     |
| `LIC_ERROR_UNHANDLED_RESPONSE`     | The server responded with an unhandled HTTP status or malformed success message.|

#### `lic_client_datastore`

This is an **opaque handle** to the client datastore. It holds all credentials and session state. You cannot access its members directly. Instead, use the `lic_client_get_*` accessor functions. An instance of this handle is created by `lic_client_parse_secret_file` and must be freed with `lic_client_free_datastore`.

-----

### Public Functions

#### Setup and Teardown

`lic_client_status lic_client_parse_secret_file(const char* file_path, const char* password, lic_client_datastore** datastore_ptr);`

  * **Description**: Parses a client secret file (`.json` or `.enc.json`) and initializes a datastore handle. This is the first function you should call.
  * **Parameters**:
      * `file_path`: Path to the client secret file.
      * `password`: The password for an encrypted file. Pass `NULL` for a plain-text file.
      * `datastore_ptr`: A pointer to a `lic_client_datastore*` that will be populated with the new handle on success.
  * **Returns**: `LIC_SUCCESS` on success, or an error code on failure. On success, the caller is responsible for freeing the created datastore with `lic_client_free_datastore`.

`void lic_client_free_datastore(lic_client_datastore* store);`

  * **Description**: Frees all memory associated with a datastore handle.
  * **Parameters**:
      * `store`: The datastore handle to free.

`const char* lic_client_status_to_string(lic_client_status status);`

  * **Description**: Converts a `lic_client_status` enum into a human-readable, constant string.
  * **Parameters**:
      * `status`: The status code to convert.
  * **Returns**: A string describing the status.

#### Authentication Workflow

`lic_client_status lic_client_authenticate(lic_client_datastore* store);`

  * **Description**: Performs the full mutual authentication handshake with the server. On success, the datastore is updated with a session token and any custom content from the license.
  * **Parameters**:
      * `store`: A valid datastore handle created by `lic_client_parse_secret_file`.
  * **Returns**: `LIC_SUCCESS` on success, or an error code.

`lic_client_status lic_client_keepalive(lic_client_datastore* store);`

  * **Description**: Sends a keepalive message to the server to maintain the session. This should be called periodically after a successful authentication.
  * **Parameters**:
      * `store`: A valid, authenticated datastore handle.
  * **Returns**: `LIC_SUCCESS` if the server acknowledged the keepalive, or an error code.

`lic_client_status lic_client_release(lic_client_datastore* store);`

  * **Description**: Informs the server that the session is being terminated, allowing the license to be used by another client immediately. This should be called on graceful application shutdown.
  * **Parameters**:
      * `store`: A valid, authenticated datastore handle.
  * **Returns**: `LIC_SUCCESS` if the server acknowledged the release or if there was no session to release.

#### Configuration

`void lic_client_set_insecure_tls(lic_client_datastore* store, bool allow);`

  * **Description**: Sets the policy for TLS certificate verification. **FOR DEVELOPMENT ONLY.**
  * **Parameters**:
      * `store`: A valid datastore handle.
      * `allow`: Set to `true` to disable TLS verification (insecure). Defaults to `false` (secure).

#### Data Accessors

`const char* lic_client_get_client_id(const lic_client_datastore* store);`

  * **Returns**: The Client ID loaded from the secret file, or `NULL`.

`const char* lic_client_get_server_url(const lic_client_datastore* store);`

  * **Returns**: The Server URL loaded from the secret file, or `NULL`.

`const char* lic_client_get_session_token(const lic_client_datastore* store);`

  * **Returns**: The session token received after authentication, or `NULL` if not authenticated.

`const char* lic_client_get_custom_content(const lic_client_datastore* store);`

  * **Returns**: The verified custom content from the license, or `NULL` if none exists.

## Example Usage

The following example (`main.c`) shows a complete workflow: parsing a secret, authenticating, sending a keepalive, and gracefully releasing the session before exiting.

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include "lic_client.h" // Include your library's header

// Platform-specific includes for the sleep function
#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

#include <curl/curl.h>

// Helper function for a cross-platform sleep
void cross_platform_sleep(int seconds) {
    #ifdef _WIN32
        Sleep(seconds * 1000);
    #else
        sleep(seconds);
    #endif
}


int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <path_to_secret_file> [password] [--allow_insecure_tls]\n", argv[0]);
        return 1;
    }

    if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
        fprintf(stderr, "Fatal: Could not initialize libcurl.\n");
        return 1;
    }

    const char* file_path = argv[1];
    const char* password = NULL;
    bool allow_insecure = false;

    for (int i = 2; i < argc; ++i) {
        if (strcmp(argv[i], "--allow_insecure_tls") == 0) {
            allow_insecure = true;
        } else {
            password = argv[i];
        }
    }

    printf("--- 1. Attempting to parse secret file: %s\n", file_path);

    lic_client_datastore* store = NULL;
    lic_client_status status = lic_client_parse_secret_file(file_path, password, &store);

    if (status != LIC_SUCCESS) {
        fprintf(stderr, "--> FAILED to parse secret file. Status: %s (%d)\n", lic_client_status_to_string(status), status);
        curl_global_cleanup();
        return 1;
    }

    printf("--> SUCCESS: Secret file parsed successfully for ClientID: %s\n", lic_client_get_client_id(store));
    
    if (allow_insecure) {
        printf("\n--- 2. Disabling TLS certificate verification ---\n");
        printf("!!! WARNING: Not for production use. !!!\n");
        lic_client_set_insecure_tls(store, true);
    }

    printf("\n--- 3. Attempting to authenticate with server... ---\n");
    status = lic_client_authenticate(store);

    if (status != LIC_SUCCESS) {
        fprintf(stderr, "--> FAILED to authenticate. Status: %s (%d)\n", lic_client_status_to_string(status), status);
    } else {
        printf("--> SUCCESS: Authentication complete!\n");
        const char* token = lic_client_get_session_token(store);
        const char* content = lic_client_get_custom_content(store);
        printf("    Session Token: %s\n", token ? token : "N/A");
        if (content) {
             printf("    Custom Content: %s\n", content);
        }

        printf("\n--- 4. Sending keepalive message... ---\n");
        printf("(Sleeping for 2 seconds first)\n");
        cross_platform_sleep(2);

        status = lic_client_keepalive(store);

        if (status != LIC_SUCCESS) {
            fprintf(stderr, "--> FAILED to send keepalive. Status: %s (%d)\n", lic_client_status_to_string(status), status);
        } else {
            printf("--> SUCCESS: Keepalive acknowledged by server.\n");
        }
    }

    // --- NEW: Gracefully release the session before freeing resources ---
    if (store && lic_client_get_session_token(store)) {
        printf("\n--- 5. Releasing the session... ---\n");
        status = lic_client_release(store);
        if (status != LIC_SUCCESS) {
            fprintf(stderr, "--> FAILED to release session. Status: %s (%d)\n", lic_client_status_to_string(status), status);
        } else {
            printf("--> SUCCESS: Session released.\n");
        }
    }

    printf("\nCleaning up and exiting.\n");
    lic_client_free_datastore(store);
    curl_global_cleanup();

    return 0;
}
```