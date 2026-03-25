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

const char* read_shared_secret() {
    char *shared_secret = getenv("LASTFM_SHARED_SECRET");
    if (!shared_secret) {
        fprintf(stderr, "LASTFM_SHARED_SECRET environment variable not set\n");
        exit(1);
    }

    return shared_secret;
}

const char* read_session_key() {
    char *session_key = getenv("LASTFM_SESSION_KEY");
    if (!session_key) {
        fprintf(stderr, "LASTFM_SESSION_KEY environment variable not set\n");
        exit(1);
    }

    return session_key;
}

void wait_for_enter(void) {
    printf("Press Enter to continue...");
    fflush(stdout);

    while (getchar() != '\n');
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

    // step 1: (implicit) get yer own API key
    const char* api_key = read_api_key();
    const char* shared_secret = read_shared_secret();
    const char* session_key = read_session_key();

    // step 2: get token
    if (!scrob_set_client_api_key(client, api_key)) {
        fprintf(stderr, "Failed to set API key\n");
        scrob_destroy_client(client);
        return 1;
    }

    if (!scrob_set_client_shared_secret(client, shared_secret)) {
        fprintf(stderr, "Failed to set shared secret\n");
        scrob_destroy_client(client);
        return 1;
    }

    if (scrob_set_client_session_key(client, session_key)) {
        printf("Session key already set, skipping authentication flow\n");
        goto got_session_key;
    }

    scrob_get_client_token(client); // This will print the request URL for debugging

    // step 3: rq auth from the user
    const char* auth_url = scrob_get_auth_url(client);
    if (auth_url) {
    #ifdef LINUX
        char command[512];
        snprintf(command, sizeof(command), "xdg-open \"%s\"", auth_url);
        system(command); // Open the URL in the default browser on Linux
    #else
        printf("Please open the following URL in your browser to authenticate:\n%s\n", auth_url);
    #endif
    printf("After authenticating, press Enter to continue...\n");
    wait_for_enter();
    } else {
        fprintf(stderr, "Failed to get authentication URL\n");
    }

    // step 4: fetch session key
    scrob_get_session_key(client); // This will print the response for debugging

got_session_key:

    // Additional client operations would go here

    scrob_destroy_client(client);
    return 0;
}
