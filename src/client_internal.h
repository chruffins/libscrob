#ifndef SCROB_CLIENT_INTERNAL_H
#define SCROB_CLIENT_INTERNAL_H

#define SCROB_API_KEY_LENGTH         32
#define SCROB_API_KEY_STR_LENGTH     33
#define SCROB_MD5_DIGEST_BINARY_SIZE 16
#define SCROB_MD5_DIGEST_HEX_SIZE    33
#define SCROB_BUFFER_SIZE            512

struct scrob_client {
    char api_key[SCROB_API_KEY_STR_LENGTH];
    char shared_secret[SCROB_API_KEY_STR_LENGTH];
    char api_sig_buffer[SCROB_MD5_DIGEST_HEX_SIZE];
    char token_buffer[SCROB_API_KEY_STR_LENGTH];
    char session_key_buffer[SCROB_API_KEY_STR_LENGTH];

    bool is_authenticated;
};

#endif