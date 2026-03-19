#include "authentication.h"

#include "md5.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    const char *name;
    const char *value;
} scrob_param_pair;

static int scrob_compare_param_pairs(const void *a, const void *b) {
    const scrob_param_pair *pair_a = (const scrob_param_pair *)a;
    const scrob_param_pair *pair_b = (const scrob_param_pair *)b;
    return strcmp(pair_a->name, pair_b->name);
}

const char *scrob_create_api_signature_for_get_token(const char *api_key) {
    char* api_sig = (char *)malloc(17); // 16 bytes + null terminator
    if (!api_sig) {
        return NULL;
    }

    char buffer[64] = {0};
    int len = snprintf(buffer, sizeof(buffer), "api_key%s", api_key);
    if (len < 0 || (size_t)len >= sizeof(buffer)) {
        free(api_sig);
        return NULL;
    }

    scrob_md5_ctx ctx;
    scrob_md5_init(&ctx);
    scrob_md5_update(&ctx, (const uint8_t *)buffer, len);
    scrob_md5_final((uint8_t *)api_sig, &ctx);
    return api_sig;
}

const char *scrob_create_api_signature(const char **param_names, const char **param_values, size_t num_params) {
    if (!param_names || !param_values || num_params == 0) {
        return NULL;
    }

    char *api_sig = (char *)malloc(17); // 16 bytes + null terminator
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
            return NULL;
        }

        pairs[i].name = param_names[i];
        pairs[i].value = param_values[i];
        total_len += strlen(param_names[i]) + strlen(param_values[i]);
    }

    qsort(pairs, num_params, sizeof(scrob_param_pair), scrob_compare_param_pairs);

    char *buffer = (char *)malloc(total_len + 1);
    if (!buffer) {
        free(pairs);
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
    buffer[offset] = '\0';

    scrob_md5_ctx ctx;
    scrob_md5_init(&ctx);
    scrob_md5_update(&ctx, (const uint8_t *)buffer, offset);
    scrob_md5_final((uint8_t *)api_sig, &ctx);
    api_sig[16] = '\0';

    free(buffer);
    free(pairs);

    return api_sig;
}
