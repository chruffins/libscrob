#ifndef SCROB_AUTH_H
#define SCROB_AUTH_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// ownership model: caller is responsible for freeing the returned string

const char* scrob_create_api_signature_for_get_token(const char* api_key);
const char* scrob_create_api_signature(const char** param_names, const char** param_values, size_t num_params);

const char* scrob_request_auth_from_user(const char* api_key, const char* token);

#ifdef __cplusplus
}
#endif

#endif