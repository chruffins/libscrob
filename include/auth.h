#ifndef SCROB_AUTH_H
#define SCROB_AUTH_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct scrob_client scrob_client;

// returns 0 on success, non-zero on failure
int scrob_get_client_token(scrob_client* client);

// returns 0 on success, non-zero on failure
int scrob_get_session_key(scrob_client* client);

// must be freed by caller
const char* scrob_get_auth_url(scrob_client* client);

#ifdef __cplusplus
}
#endif

#endif