#include "../include/scrob.h"
#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>

#define LIBSCROBBLER_VERSION "0.1.0"

static bool scrob_initialized = false;

bool scrob_init(void) {
    CURLcode res = curl_global_init(CURL_GLOBAL_DEFAULT);
    if (res == CURLE_OK) {
        scrob_initialized = true;
    }
    return res == CURLE_OK;
}

bool scrob_is_initialized(void) {
    return scrob_initialized;
}

const char* scrob_version(void) {
    return LIBSCROBBLER_VERSION;
}
