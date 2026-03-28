#ifndef SCROB_AUTH_H
#define SCROB_AUTH_H

typedef struct scrob_client scrob_client;

// returns 0 on success, non-zero on failure
int scrob_get_client_token(scrob_client* client);

// returns 0 on success, non-zero on failure
int scrob_get_session_key(scrob_client* client);

const char* scrob_get_auth_url(scrob_client* client);

#endif