#include "auth.h"

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "client.h"
#include "client_internal.h"
#include "xml.h"
#include "api.h"

int scrob_get_client_token(scrob_client* client) {
    int retcode = 1;
    if (!client) {
        return retcode;
    }

    if (strlen(client->api_key) == 0 || strlen(client->shared_secret) == 0) {
        return retcode;
    }

    char buffer[SCROB_BUFFER_SIZE] = {0};
    const char *sig_param_names[2] = {"api_key", "method"};
    const char *sig_param_values[2] = {client->api_key, "auth.getToken"};
    const char *api_sig = scrob_create_api_signature(sig_param_names, sig_param_values, 2, client->shared_secret);
    const char *param_names[3] = {"method", "api_key", "api_sig"};
    const char *param_values[3] = {"auth.getToken", client->api_key, api_sig};

    if (!api_sig) {
        return retcode;
    }

    const char* request_url = scrob_build_request_url(SCROB_API_ENDPOINT, param_names, param_values, 3);
    if (!request_url) {
        free((char*)api_sig);
        return retcode;
    }

    scrob_response_buffer response = {0};
    struct xml_document *doc = NULL;

    if (scrob_perform_request(request_url, NULL, &response) == 0 && response.data) {
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
        }

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
        }

        xml_string_copy_terminated(xml_node_content(token_node), (uint8_t*)client->token_buffer, sizeof(client->token_buffer));
        printf("Received token: %s\n", client->token_buffer);

        xml_document_free(doc, false);
        retcode = 0;
    } else {
        fprintf(stderr, "Failed to perform API request\n");
    }

cleanup:
    free((char*)request_url);
    free((char*)api_sig);
    free(response.data);
    return retcode;
}

int scrob_get_session_key(scrob_client *client) {
    int retcode = 1;
    if (!client) {
        return retcode;
    }

    if (strlen(client->api_key) == 0 || strlen(client->token_buffer) == 0 || strlen(client->shared_secret) == 0) {
        return retcode;
    }

    char buffer[SCROB_BUFFER_SIZE] = {0};
    const char *param_names[4] = {"method", "api_key", "token", "api_sig"};
    const char *param_values[4] = {"auth.getSession", client->api_key, client->token_buffer, NULL};
    const char *api_sig = scrob_create_api_signature(param_names, param_values, 3, client->shared_secret);

    if (!api_sig) {
        return retcode;
    }

    param_values[3] = api_sig;
    const char *request_url = scrob_build_request_url(SCROB_API_ENDPOINT, param_names, param_values, 4);
    if (!request_url) {
        free((char*)api_sig);
        return retcode;
    }

    scrob_response_buffer response = {0};
    struct xml_document *doc = NULL;

    if (scrob_perform_request(request_url, NULL, &response) == 0 && response.data) {
        printf("%s", response.data);
    }

    free((char*)api_sig);
    free((char*)request_url);

    doc = xml_parse_document((uint8_t *)response.data, response.length);
    if (!doc) {
        fprintf(stderr, "Failed to parse XML response\n");
        free(response.data);
        return retcode;
    }

    struct xml_node *root = xml_document_root(doc);
    int error_code = scrob_get_error_code_from_response(root);
    if (error_code) {
        fprintf(stderr, "API error code: %d\n", error_code);
        retcode = error_code;
        goto xml_cleanup;
    }

    struct xml_node *session_node = xml_node_child(root, 0);
    if (!session_node) {
        fprintf(stderr, "Unexpected response format: no child nodes\n");
        goto xml_cleanup;
    }

    xml_string_copy_terminated(xml_node_name(session_node), (uint8_t *)buffer, sizeof(buffer));
    if (strcmp(buffer, "session") != 0) {
        fprintf(stderr, "Unexpected response format: expected 'session' node, got '%s'\n", buffer);
        goto xml_cleanup;
    }

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
    size_t predicted_len = 46 + api_key_len + token_len + 1;

    if (token_len == 0 || api_key_len == 0) {
        printf("Cannot generate auth URL: missing API key or token\n");
        return NULL;
    }

    char* auth_url = malloc(predicted_len * sizeof(char));
    if (!auth_url) {
        return NULL;
    }

    int len = snprintf(auth_url, predicted_len, "https://www.last.fm/api/auth/?api_key=%s&token=%s", client->api_key, client->token_buffer);
    if (len < 0 || (size_t)len >= predicted_len) {
        free(auth_url);
        return NULL;
    }

    return auth_url;
}
