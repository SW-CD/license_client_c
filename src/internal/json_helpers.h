#ifndef JSON_HELPERS_INTERNAL_H
#define JSON_HELPERS_INTERNAL_H

#include <jansson.h>

/**
 * @brief Safely gets a string value from a JSON object.
 *
 * @param obj The Jansson JSON object.
 * @param key The key for the desired string value.
 * @return A const pointer to the string value if it exists and is a string,
 * otherwise NULL.
 */
const char* json_get_string(json_t *obj, const char *key);

#endif // JSON_HELPERS_INTERNAL_H
