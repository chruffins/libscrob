#include "client.h"

#include <curl/curl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "xml.h"
#include "authentication.h"

struct scrob_client {
    char api_key[33]; // 32 + 1
    char api_sig_buffer[17]; // 16 bytes + 1
    char token_buffer[33]; // 32 + 1

    bool is_authenticated;
};

typedef struct {
    char *data;
    size_t length;
} scrob_response_buffer;

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
    int len;
    const char *api_sig = scrob_create_api_signature_for_get_token(client->api_key); // print as hex

    if (!api_sig) {
        curl_easy_cleanup(curl);
        return retcode;
    }

    len = snprintf(buffer, sizeof(buffer), "%s?method=auth.getToken&api_key=%s&api_sig=%s", SCROB_API_ENDPOINT, client->api_key, api_sig);
    if (len < 0 || (size_t)len >= sizeof(buffer) || curl_easy_setopt(curl, CURLOPT_URL, buffer) != CURLE_OK) {
        free((void *)api_sig);
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
    free((void *)api_sig);
    free(response.data);
    curl_easy_cleanup(curl); // yea
    return retcode;
}