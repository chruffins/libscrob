#include "api.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

#include "md5.h"
#include "xml.h"
#include "client_internal.h"

typedef struct {
    const char *name;
    const char *value;
} scrob_param_pair;

static int scrob_compare_param_pairs(const void *a, const void *b) {
    const scrob_param_pair *pair_a = (const scrob_param_pair *)a;
    const scrob_param_pair *pair_b = (const scrob_param_pair *)b;
    return strcmp(pair_a->name, pair_b->name);
}

static char *scrob_build_param_string(
    const char *endpoint,
    const char **param_names,
    const char **param_values,
    size_t param_count,
    char prefix
) {
    size_t endpoint_len = endpoint ? strlen(endpoint) : 0;
    size_t total_len = endpoint_len;

    if (param_count > 0) {
        if (!param_names || !param_values) {
            return NULL;
        }

        if (prefix != '\0') {
            total_len += 1;
        }
    }

    for (size_t i = 0; i < param_count; ++i) {
        const char *name = param_names[i];
        const char *value = param_values[i];
        if (!name || !value) {
            return NULL;
        }

        total_len += strlen(name) + 1 + strlen(value);
        if (i + 1 < param_count) {
            total_len += 1;
        }
    }

    char *result = (char *)malloc(total_len + 1);
    if (!result) {
        return NULL;
    }

    char *cursor = result;
    if (endpoint_len > 0) {
        memcpy(cursor, endpoint, endpoint_len);
        cursor += endpoint_len;
    }

    if (param_count > 0 && prefix != '\0') {
        *cursor++ = prefix;
    }

    for (size_t i = 0; i < param_count; ++i) {
        size_t name_len = strlen(param_names[i]);
        size_t value_len = strlen(param_values[i]);

        memcpy(cursor, param_names[i], name_len);
        cursor += name_len;
        *cursor++ = '=';
        memcpy(cursor, param_values[i], value_len);
        cursor += value_len;

        if (i + 1 < param_count) {
            *cursor++ = '&';
        }
    }

    *cursor = '\0';
    return result;
}

const char *scrob_build_request_url(
    const char *endpoint,
    const char **param_names,
    const char **param_values,
    size_t param_count
) {
    if (!endpoint) {
        return NULL;
    }
    return scrob_build_param_string(endpoint, param_names, param_values, param_count, '?');
}

const char *scrob_build_postfields(
    const char **param_names,
    const char **param_values,
    size_t param_count
) {
    return scrob_build_param_string(NULL, param_names, param_values, param_count, '\0');
}

size_t scrob_write_response_body(void *contents, size_t size, size_t nmemb, void *userp) {
    if (!userp) {
        return 0;
    }

    size_t total_size = size * nmemb;
    scrob_response_buffer *buffer = (scrob_response_buffer *)userp;

    char *new_data = (char *)realloc(buffer->data, buffer->length + total_size + 1);
    if (!new_data) {
        return 0;
    }

    buffer->data = new_data;
    memcpy(buffer->data + buffer->length, contents, total_size);
    buffer->length += total_size;
    buffer->data[buffer->length] = '\0';

    return total_size;
}

int scrob_get_error_code_from_response(struct xml_node *root) {
    if (!root) {
        return 0;
    }

    char str_buffer[64] = {0};
    xml_string_copy_terminated(xml_node_name(root), (uint8_t *)str_buffer, sizeof(str_buffer));
    if (strcmp(str_buffer, "lfm") != 0) {
        return 0;
    }

    bool is_failed = false;
    size_t attribute_count = xml_node_attributes(root);
    for (size_t i = 0; i < attribute_count; ++i) {
        xml_string_copy_terminated(xml_node_attribute_name(root, i), (uint8_t *)str_buffer, sizeof(str_buffer));
        if (strcmp(str_buffer, "status") != 0) {
            continue;
        }

        xml_string_copy_terminated(xml_node_attribute_content(root, i), (uint8_t *)str_buffer, sizeof(str_buffer));
        if (strcmp(str_buffer, "ok") == 0) {
            return 0;
        }

        if (strcmp(str_buffer, "failed") == 0) {
            is_failed = true;
        }
        break;
    }

    if (!is_failed) {
        return 0;
    }

    size_t child_count = xml_node_children(root);
    for (size_t i = 0; i < child_count; ++i) {
        struct xml_node *child = xml_node_child(root, i);
        if (!child) {
            continue;
        }

        xml_string_copy_terminated(xml_node_name(child), (uint8_t *)str_buffer, sizeof(str_buffer));
        if (strcmp(str_buffer, "error") != 0) {
            continue;
        }

        size_t error_attribute_count = xml_node_attributes(child);
        for (size_t j = 0; j < error_attribute_count; ++j) {
            xml_string_copy_terminated(xml_node_attribute_name(child, j), (uint8_t *)str_buffer, sizeof(str_buffer));
            if (strcmp(str_buffer, "code") != 0) {
                continue;
            }

            xml_string_copy_terminated(xml_node_attribute_content(child, j), (uint8_t *)str_buffer, sizeof(str_buffer));
            return (int)strtol(str_buffer, NULL, 10);
        }
    }

    return 0;
}

char *scrob_create_api_signature(
    const char **param_names,
    const char **param_values,
    size_t num_params,
    const char *shared_secret
) {
    if (!param_names || !param_values || num_params == 0 || !shared_secret) {
        return NULL;
    }

    char *api_sig = (char *)malloc(SCROB_MD5_DIGEST_HEX_SIZE);
    if (!api_sig) {
        return NULL;
    }

    scrob_param_pair *pairs = (scrob_param_pair *)malloc(num_params * sizeof(scrob_param_pair));
    if (!pairs) {
        free(api_sig);
        return NULL;
    }

    size_t total_len = 0;
    for (size_t i = 0; i < num_params; ++i) {
        if (!param_names[i] || !param_values[i]) {
            free(pairs);
            free(api_sig);
            return NULL;
        }

        pairs[i].name = param_names[i];
        pairs[i].value = param_values[i];
        total_len += strlen(param_names[i]) + strlen(param_values[i]);
    }

    qsort(pairs, num_params, sizeof(scrob_param_pair), scrob_compare_param_pairs);

    size_t secret_len = strlen(shared_secret);
    char *buffer = (char *)malloc(total_len + secret_len + 1);
    if (!buffer) {
        free(pairs);
        free(api_sig);
        return NULL;
    }

    size_t offset = 0;
    for (size_t i = 0; i < num_params; ++i) {
        size_t name_len = strlen(pairs[i].name);
        size_t value_len = strlen(pairs[i].value);

        memcpy(buffer + offset, pairs[i].name, name_len);
        offset += name_len;
        memcpy(buffer + offset, pairs[i].value, value_len);
        offset += value_len;
    }

    memcpy(buffer + offset, shared_secret, secret_len);
    offset += secret_len;
    buffer[offset] = '\0';

    uint8_t binary_digest[SCROB_MD5_DIGEST_BINARY_SIZE];
    scrob_md5_ctx ctx;
    scrob_md5_init(&ctx);
    scrob_md5_update(&ctx, (const uint8_t *)buffer, offset);
    scrob_md5_final(binary_digest, &ctx);

    for (int i = 0; i < SCROB_MD5_DIGEST_BINARY_SIZE; i++) {
        snprintf(&api_sig[i * 2], 3, "%02x", binary_digest[i]);
    }

    free(buffer);
    free(pairs);

    return api_sig;
}
