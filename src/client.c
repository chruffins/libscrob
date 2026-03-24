#include "client.h"

#include <curl/curl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "authentication.h"

struct scrob_client {
    char api_key[33]; // 32 + 1
    char api_sig_buffer[17]; // 16 bytes + 1

    bool is_authenticated;
};

typedef struct {
    char *data;
    size_t length;
} scrob_response_buffer;

static size_t scrob_write_response_body(void *contents, size_t size, size_t nmemb, void *userp)
{
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

scrob_client *scrob_create_client(void)
{
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

bool scrob_set_client_api_key(scrob_client *client, const char *api_key)
{
    strncpy(client->api_key, api_key, sizeof(client->api_key) - 1);
    client->api_key[sizeof(client->api_key) - 1] = 0;
    return true;
}

void scrob_get_client_token(scrob_client* client) {
    if (strlen(client->api_key) == 0) {
        return;
    }

    CURL *curl = curl_easy_init();
    if (!curl) {
        return;
    }

    char buffer[512] = {0};
    int len;
    const char *api_sig = scrob_create_api_signature_for_get_token(client->api_key); // print as hex

    if (!api_sig) {
        curl_easy_cleanup(curl);
        return;
    }

    len = snprintf(buffer, sizeof(buffer), "%s?method=auth.getToken&api_key=%s&api_sig=%s", SCROB_API_ENDPOINT, client->api_key, api_sig);
    if (len < 0 || (size_t)len >= sizeof(buffer) || curl_easy_setopt(curl, CURLOPT_URL, buffer) != CURLE_OK) {
        free((void *)api_sig);
        curl_easy_cleanup(curl);
        return;
    }

    scrob_response_buffer response = {0};

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, scrob_write_response_body);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    if (curl_easy_perform(curl) == CURLE_OK && response.data) {
        printf("%s\n", response.data);
    }

    free((void *)api_sig);
    free(response.data);
    curl_easy_cleanup(curl); // yea
}