#ifndef SCROBCLIENT_H
#define SCROBCLIENT_H

#define SCROB_API_ENDPOINT "https://ws.audioscrobbler.com/2.0/"

#ifdef __cplusplus
    extern "C" {
#endif

#include <stdbool.h>

typedef struct scrob_client scrob_client;

scrob_client* scrob_create_client(void);
void scrob_destroy_client(scrob_client* client);

bool scrob_set_client_api_key(scrob_client* client, const char* api_key);
void scrob_get_client_token(scrob_client* client);


#ifdef __cplusplus
    }
#endif

#endif /* SCROBCLIENT_H */