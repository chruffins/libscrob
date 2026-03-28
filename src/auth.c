#include "auth.h"

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include <curl/curl.h>

#include "client.h"
#include "client_internal.h"
#include "md5.h"
#include "xml.h"
#include "api.h"

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