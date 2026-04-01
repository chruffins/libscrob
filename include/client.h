#ifndef SCROB_CLIENT_H
#define SCROB_CLIENT_H

#define SCROB_API_ENDPOINT "https://ws.audioscrobbler.com/2.0/"

#ifdef __cplusplus
    extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>

typedef struct scrob_client scrob_client;

scrob_client* scrob_create_client(void);
void scrob_destroy_client(scrob_client* client);

bool scrob_set_client_api_key(scrob_client* client, const char* api_key);
bool scrob_set_client_shared_secret(scrob_client* client, const char* shared_secret);
bool scrob_set_client_session_key(scrob_client* client, const char* session_key);

#ifdef __cplusplus
    }
#endif

#endif /* SCROB_CLIENT_H */