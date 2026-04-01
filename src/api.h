#ifndef SCROB_API_H
#define SCROB_API_H

#include <stddef.h>

typedef struct {
    char *data;
    size_t length;
} scrob_response_buffer;

struct xml_node;

// must be freed by caller
const char *scrob_build_request_url(
    const char *endpoint,
    const char **param_names,
    const char **param_values,
    size_t param_count
);

// must be freed by caller
const char *scrob_build_postfields(
    const char **param_names,
    const char **param_values,
    size_t param_count
);

size_t scrob_write_response_body(void *contents, size_t size, size_t nmemb, void *userp);

int scrob_get_error_code_from_response(struct xml_node *root);

// must be freed by caller
char *scrob_create_api_signature(
    const char **param_names,
    const char **param_values,
    size_t num_params,
    const char *shared_secret
);

#endif /* SCROB_API_H */
