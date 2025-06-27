#ifndef HTTP_HANDLER_INTERNAL_H
#define HTTP_HANDLER_INTERNAL_H

#include "lic_client.h"

/**
 * @brief Internal handler for authentication and keepalive requests.
 */
lic_client_status handle_auth_or_keepalive_request(lic_client_datastore* store, bool is_auth);

/**
 * @brief Internal handler for session release requests.
 */
lic_client_status handle_release_request(lic_client_datastore* store);

#endif // HTTP_HANDLER_INTERNAL_H