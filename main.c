#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "scrob.h"
#include "client.h"

const char* read_api_key() {
    char *api_key = getenv("LASTFM_API_KEY");
    if (!api_key) {
        fprintf(stderr, "LASTFM_API_KEY environment variable not set\n");
        exit(1);
    }

    return api_key;
}

int main(int argc, char **argv) {
    scrob_init();

    if (!scrob_is_initialized()) {
        fprintf(stderr, "Failed to initialize scrob\n");
        return 1;
    }

    printf("Scrob version: %s\n", scrob_version());

    scrob_client* client = scrob_create_client();
    if (!client) {
        fprintf(stderr, "Failed to create scrob client\n");
        return 1;
    }

    const char* api_key = read_api_key();

    if (!scrob_set_client_api_key(client, api_key)) {
        fprintf(stderr, "Failed to set API key\n");
        scrob_destroy_client(client);
        return 1;
    }

    scrob_get_client_token(client); // This will print the request URL for debugging

    // Additional client operations would go here

    scrob_destroy_client(client);
    return 0;
}
