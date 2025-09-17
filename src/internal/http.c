#include "http.h"
#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>

// A struct to hold the response data from libcurl
struct memory_struct {
    char* memory;
    size_t size;
};

// Callback function for libcurl to write response data into our struct
static size_t write_memory_callback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t realsize = size * nmemb;
    struct memory_struct* mem = (struct memory_struct*)userp;

    char* ptr = realloc(mem->memory, mem->size + realsize + 1);
    if (ptr == NULL) {
        // Out of memory!
        fprintf(stderr, "HTTP_ERROR: not enough memory (realloc returned NULL)\n");
        return 0;
    }

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

char* http_post_json(const char* url, const char* post_data, bool allow_insecure, long timeout_ms, long* http_status_code) {
    CURL* curl_handle;
    CURLcode res;

    struct memory_struct chunk;
    chunk.memory = malloc(1);
    chunk.size = 0;

    curl_handle = curl_easy_init();
    if (!curl_handle) {
        free(chunk.memory);
        return NULL;
    }

    struct curl_slist* headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    
    curl_easy_setopt(curl_handle, CURLOPT_URL, url);
    curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, post_data);
    curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, write_memory_callback);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void*)&chunk);
    curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "lic-client-c/1.0");
    curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT_MS, timeout_ms);

    if (allow_insecure) {
        curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, 0L);
    }
    
    res = curl_easy_perform(curl_handle);

    if (res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        free(chunk.memory);
        chunk.memory = NULL;
    } else {
        curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, http_status_code);
    }
    
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl_handle);

    return chunk.memory;
}