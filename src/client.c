#include "client.h"

#include <curl/curl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "xml.h"
#include "md5.h"

struct scrob_client {
    char api_key[33]; // 32 + 1
    char shared_secret[33]; // 32 + 1
    char api_sig_buffer[17]; // 16 bytes + 1
    char token_buffer[33]; // 32 + 1
    char session_key_buffer[33]; // 32 + 1

    bool is_authenticated;
};

typedef struct {
    char *data;
    size_t length;
} scrob_response_buffer;

typedef struct {
    const char *name;
    const char *value;
} scrob_param_pair;

static int scrob_compare_param_pairs(const void *a, const void *b) {
    const scrob_param_pair *pair_a = (const scrob_param_pair *)a;
    const scrob_param_pair *pair_b = (const scrob_param_pair *)b;
    return strcmp(pair_a->name, pair_b->name);
}

static const char *scrob_create_api_signature_for_get_token(const char *api_key) {
    char* hex_sig = (char *)malloc(33);
    if (!hex_sig) {
        return NULL;
    }

    char buffer[64] = {0};
    int len = snprintf(buffer, sizeof(buffer), "api_key%s", api_key);
    if (len < 0 || (size_t)len >= sizeof(buffer)) {
        free(hex_sig);
        return NULL;
    }

    printf("string to hash: %s\n", buffer); // debug print

    uint8_t binary_digest[16];
    scrob_md5_ctx ctx;
    scrob_md5_init(&ctx);
    scrob_md5_update(&ctx, (const uint8_t *)buffer, len);
    scrob_md5_final(binary_digest, &ctx);

    for (int i = 0; i < 16; i++) {
        snprintf(&hex_sig[i * 2], 3, "%02x", binary_digest[i]);
    }

    return hex_sig;
}

static const char *scrob_create_api_signature(const char **param_names, const char **param_values, size_t num_params, const char *shared_secret) {
    if (!param_names || !param_values || num_params == 0 || !shared_secret) {
        return NULL;
    }

    char *api_sig = (char *)malloc(33);
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

    size_t secret_len = strlen(shared_secret);
    char *buffer = (char *)malloc(total_len + secret_len + 1);
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
    memcpy(buffer + offset, shared_secret, secret_len);
    offset += secret_len;
    buffer[offset] = '\0';

    printf("string to hash: %s\n", buffer); // debug print

    uint8_t binary_digest[16];
    scrob_md5_ctx ctx;
    scrob_md5_init(&ctx);
    scrob_md5_update(&ctx, (const uint8_t *)buffer, offset);
    scrob_md5_final(binary_digest, &ctx);

    for (int i = 0; i < 16; i++) {
        snprintf(&api_sig[i * 2], 3, "%02x", binary_digest[i]);
    }

    free(buffer);
    free(pairs);

    return api_sig;
}

static const char *scrob_build_request_url(
    const char *endpoint,
    const char *const param_names[],
    const char *const param_values[],
    size_t param_count
) {
    if (!endpoint) {
        return NULL;
    }

    size_t endpoint_len = strlen(endpoint);
    size_t total_len = endpoint_len;

    if (param_count > 0) {
        if (!param_names || !param_values) {
            return NULL;
        }
        total_len += 1; // '?'
    }

    for (size_t i = 0; i < param_count; ++i) {
        const char *name = param_names[i];
        const char *value = param_values[i];
        if (!name || !value) {
            return NULL;
        }

        total_len += strlen(name) + 1 + strlen(value); // name + '=' + value
        if (i + 1 < param_count) {
            total_len += 1; // '&'
        }
    }

    char *url = (char *)malloc(total_len + 1);
    if (!url) {
        return NULL;
    }

    char *cursor = url;
    memcpy(cursor, endpoint, endpoint_len);
    cursor += endpoint_len;

    if (param_count > 0) {
        *cursor++ = '?';
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
    return url;
}

static size_t scrob_write_response_body(void *contents, size_t size, size_t nmemb, void *userp) {
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

static int scrob_get_error_code_from_response(struct xml_node *root) {
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

scrob_client *scrob_create_client(void) {
    scrob_client *client = (scrob_client *)malloc(sizeof(scrob_client));
    if (!client) {
        return NULL;
    }

    memset(client, 0, sizeof(scrob_client));

    return client;
}

void scrob_destroy_client(scrob_client* client) {
    if (client) {
        free(client);
    }
}

bool scrob_set_client_api_key(scrob_client *client, const char *api_key) {
    if (!client || !api_key || strlen(api_key) != 32) {
        return false;
    }
    strncpy(client->api_key, api_key, sizeof(client->api_key) - 1);
    client->api_key[sizeof(client->api_key) - 1] = 0;
    return true;
}

bool scrob_set_client_shared_secret(scrob_client *client, const char *shared_secret) {
    if (!client || !shared_secret || strlen(shared_secret) != 32) {
        return false;
    }
    strncpy(client->shared_secret, shared_secret, sizeof(client->shared_secret) - 1);
    client->shared_secret[sizeof(client->shared_secret) - 1] = 0;
    return true;
}

bool scrob_set_client_session_key(scrob_client *client, const char *session_key) {
    if (!client || !session_key || strlen(session_key) != 32) {
        return false;
    }
    strncpy(client->session_key_buffer, session_key, sizeof(client->session_key_buffer) - 1);
    client->session_key_buffer[sizeof(client->session_key_buffer) - 1] = 0;
    client->is_authenticated = true; // assumes this is true anyways
    return true;
}

int scrob_get_client_token(scrob_client* client) {
    int retcode = 1; // default to failure
    if (strlen(client->api_key) == 0) {
        return retcode;
    }

    CURL *curl = curl_easy_init();
    if (!curl) {
        return retcode;
    }

    char buffer[512] = {0};
    const char *api_sig = scrob_create_api_signature_for_get_token(client->api_key); // print as hex
    const char *param_names[3] = {"method", "api_key", "api_sig"};
    const char *param_values[3] = {"auth.getToken", client->api_key, api_sig};
    

    if (!api_sig) {
        curl_easy_cleanup(curl);
        return retcode;
    }

    const char* request_url = scrob_build_request_url(SCROB_API_ENDPOINT, param_names, param_values, 3);
    if (!request_url || curl_easy_setopt(curl, CURLOPT_URL, request_url) != CURLE_OK) {
        free((char*)request_url);
        free((char*)api_sig);
        curl_easy_cleanup(curl);
        return retcode;
    }

    scrob_response_buffer response = {0};
    struct xml_document *doc = NULL;

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, scrob_write_response_body);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    if (curl_easy_perform(curl) == CURLE_OK && response.data) {
        printf("%s", response.data);
    }

    doc = xml_parse_document((uint8_t *)response.data, response.length);
    if (doc) {
        struct xml_node *root = xml_document_root(doc);
        int error_code = scrob_get_error_code_from_response(root);
        if (error_code) {
            fprintf(stderr, "API error code: %d\n", error_code);
            retcode = error_code;
            xml_document_free(doc, false);
            goto cleanup;
        } else {
            printf("Token request successful\n");
        }

        // actually grab the token now
        // we expect the response to look like <lfm status="ok"><token>...</token></lfm>
        struct xml_node *token_node = xml_node_child(root, 0);
        if (!token_node) {
            fprintf(stderr, "Unexpected response format: no child nodes\n");
            xml_document_free(doc, false);
            goto cleanup;
        }

        xml_string_copy_terminated(xml_node_name(token_node), (uint8_t *)buffer, sizeof(buffer));
        if (strcmp(buffer, "token") != 0) {
            fprintf(stderr, "Unexpected response format: expected 'token' node, got '%s'\n", buffer);
            xml_document_free(doc, false);
            goto cleanup;
        } else {
            xml_string_copy_terminated(xml_node_content(token_node), (uint8_t*)client->token_buffer, sizeof(client->token_buffer));
            printf("Received token: %s\n", client->token_buffer);
        }

        xml_document_free(doc, false);
        retcode = 0;
    } else {
        fprintf(stderr, "Failed to perform API request\n");
    }

cleanup:
    free((char*)request_url);
    free((char*)api_sig);
    free(response.data);
    curl_easy_cleanup(curl); // yea
    return retcode;
}

int scrob_get_session_key(scrob_client *client) {
    int retcode = 1; // default to failure
    if (strlen(client->api_key) == 0 || strlen(client->token_buffer) == 0) {
         return retcode;
    }

    CURL *curl = curl_easy_init();
    if (!curl) {
        return retcode;
    }

    char buffer[512] = {0};
    const char *param_names[4] = {"method", "api_key", "token", "api_sig"};
    const char *param_values[4] = {"auth.getSession", client->api_key, client->token_buffer, NULL};
    const char *api_sig = scrob_create_api_signature(param_names, param_values, 3, client->shared_secret); // needs to be free'd

    if (!api_sig) {
        curl_easy_cleanup(curl);
        return retcode;
    }

    param_values[3] = api_sig;
    const char *request_url = scrob_build_request_url(SCROB_API_ENDPOINT, param_names, param_values, 4); // also needs free'd

    if (!request_url || curl_easy_setopt(curl, CURLOPT_URL, request_url) != CURLE_OK) {
        free((char*)api_sig);
        free((char*)request_url);
        curl_easy_cleanup(curl);
        return retcode;
    }

    printf("Requesting session key with URL: %s\n", request_url); // debug print

    scrob_response_buffer response = {0};
    struct xml_document *doc = NULL;

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, scrob_write_response_body);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    if (curl_easy_perform(curl) == CURLE_OK && response.data) {
        printf("%s", response.data);
    }

    // *dont* need these resources anymore
    free((char*)api_sig);
    free((char*)request_url);
    curl_easy_cleanup(curl);

    doc = xml_parse_document((uint8_t *)response.data, response.length);
    if (!doc) {
        fprintf(stderr, "Failed to parse XML response\n");
        return retcode;
    }

    struct xml_node *root = xml_document_root(doc);
    int error_code = scrob_get_error_code_from_response(root);
    if (error_code) {
        fprintf(stderr, "API error code: %d\n", error_code);
        retcode = error_code;
        goto xml_cleanup;
    } else {
        printf("Session key request successful\n");
    }

    // root should only have one child: session
    struct xml_node *session_node = xml_node_child(root, 0);
    if (!session_node) {
        fprintf(stderr, "Unexpected response format: no child nodes\n");
        goto xml_cleanup;
    }

    // validate name
    xml_string_copy_terminated(xml_node_name(session_node), (uint8_t *)buffer, sizeof(buffer));
    if (strcmp(buffer, "session") != 0) {
        fprintf(stderr, "Unexpected response format: expected 'session' node, got '%s'\n", buffer);
        goto xml_cleanup;
    }

    // session node should have two children: name and key
    int session_child_count = xml_node_children(session_node);
    for (int i = 0; i < session_child_count; i++) {
        struct xml_node *child = xml_node_child(session_node, i);

        xml_string_copy_terminated(xml_node_name(child), (uint8_t *)buffer, sizeof(buffer));
        if (strcmp(buffer, "key") == 0) {
            xml_string_copy_terminated(xml_node_content(child), (uint8_t *)client->session_key_buffer, sizeof(client->session_key_buffer));
            printf("Received session key: %s\n", client->session_key_buffer);
            client->is_authenticated = true;
            retcode = 0;
            break;
        }
    }

xml_cleanup:
    xml_document_free(doc, false);
    free(response.data);
    return retcode;
}

const char *scrob_get_auth_url(scrob_client *client) {
    size_t token_len = strlen(client->token_buffer);
    size_t api_key_len = strlen(client->api_key);
    size_t predicted_len = 46 + api_key_len + token_len + 1; // +1 for null terminator

    if (token_len == 0 || api_key_len == 0) {
        printf("Cannot generate auth URL: missing API key or token\n");
        return NULL;
    }

    char* auth_url = malloc(predicted_len * sizeof(char));
    int len = snprintf(auth_url, predicted_len, "https://www.last.fm/api/auth/?api_key=%s&token=%s", client->api_key, client->token_buffer);
    if (len < 0 || (size_t)len >= predicted_len) {
        free(auth_url);
        return NULL;
    }
    return auth_url;
}