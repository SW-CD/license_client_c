#include "json_helpers.h"

const char* json_get_string(json_t *obj, const char *key) {
    if (!obj || !key) {
        return NULL;
    }
    json_t *value = json_object_get(obj, key);
    if (!json_is_string(value)) {
        return NULL;
    }
    return json_string_value(value);
}
