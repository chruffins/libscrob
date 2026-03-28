#ifndef SCROB_CLIENT_INTERNAL_H
#define SCROB_CLIENT_INTERNAL_H

struct scrob_client {
    char api_key[33]; // 32 + 1
    char shared_secret[33]; // 32 + 1
    char api_sig_buffer[17]; // 16 bytes + 1
    char token_buffer[33]; // 32 + 1
    char session_key_buffer[33]; // 32 + 1

    bool is_authenticated;
};

#endif