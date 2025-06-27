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