#ifndef SCROBCLIENT_H
#define SCROBCLIENT_H

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

// returns 0 on success, non-zero on failure
int scrob_get_client_token(scrob_client* client);

// returns 0 on success, non-zero on failure
int scrob_get_session_key(scrob_client* client);

const char* scrob_get_auth_url(scrob_client* client);

#ifdef __cplusplus
    }
#endif

#endif /* SCROBCLIENT_H */