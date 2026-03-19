#include "client.h"

struct scrob_client {
    char api_key[33]; // 32 + 1
    char api_sig_buffer[17]; // 16 bytes + 1

    bool is_authenticated;
};