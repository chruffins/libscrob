#include "client.h"

#include <curl/curl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "xml.h"
#include "md5.h"
#include "api.h"

#include "client_internal.h"

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