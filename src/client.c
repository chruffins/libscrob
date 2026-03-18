#include "client.h"

struct scrob_client {
    char api_key[33]; // 32 characters + null terminator
    

    bool is_authenticated;
};