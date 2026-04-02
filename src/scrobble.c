#include "scrobble.h"
#include "client.h"
#include "client_internal.h"
#include "api.h"
#include "xml.h"

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

struct scrob_track {
    char *artist;
    char *title;
    char *album;
    unsigned int timestamp;
};

static char* scrob_strdup(const char *s) {
    if (!s) {
        return NULL;
    }
    size_t len = strlen(s);
    char *copy = (char *)malloc(len + 1);
    if (!copy) {
        return NULL;
    }
    memcpy(copy, s, len);
    copy[len] = '\0';
    return copy;
};

// interface with scrobble API
int scrob_scrobble_track(scrob_client *client, const scrob_track *track) {
    if (!track) {
        return 1;
    }

    return scrob_easy_scrobble(client, track->artist, track->title, track->timestamp);
}

int scrob_easy_scrobble(scrob_client *client, const char *artist, const char *track_title, unsigned int utc_timestamp) {
    if (client == NULL || artist == NULL || track_title == NULL || client->is_authenticated == false) {
        return 1; // failure
    }

    char *params[7] = {"api_key", "artist0", "method", "sk", "timestamp0", "track0", "api_sig"};
    char *values[7] = {client->api_key, (char*)artist, "track.scrobble", client->session_key_buffer, NULL, (char*)track_title, NULL};

    char *timestamp_str = malloc(11); // enough for 10 digits + null terminator
    if (!timestamp_str) {
        return 1; // failure
    }

    snprintf(timestamp_str, 11, "%u", utc_timestamp);
    values[4] = timestamp_str;

    const char* api_sig = scrob_create_api_signature((const char **)params, (const char **)values, 6, client->shared_secret); // need 2 free after POST
    if (!api_sig) {
        free(timestamp_str);
        return 1; // failure
    }
    values[6] = (char *)api_sig;

    const char* postfields = scrob_build_postfields((const char **)params, (const char **)values, 7); // also needs free after POST
    if (!postfields) {
        free(timestamp_str);
        free((char*)api_sig);
        free((char*)postfields);
        return 1; // failure
    }

    scrob_response_buffer response = {0};
    struct xml_document *doc = NULL;

    if (scrob_perform_request(SCROB_API_ENDPOINT, postfields, &response) == 0 && response.data) {
        printf("%s", response.data);
    }

    // *dont* need these resources anymore
    free((char*)api_sig);
    free((char*)postfields);
    free(timestamp_str);

    doc = xml_parse_document((uint8_t*)response.data, response.length);
    if (!doc) {
        fprintf(stderr, "Failed to parse XML response\n");
        free(response.data);
        return 1; // failure
    }

    struct xml_node *root = xml_document_root(doc);
    int error_code = scrob_get_error_code_from_response(root);
    if (error_code) {
        fprintf(stderr, "API error code: %d\n", error_code);
        xml_document_free(doc, false);
        free(response.data);
        return error_code; // failure with API error code
    }

    xml_document_free(doc, false);
    free(response.data);
    return 0; // success
}

// scrob track struct
scrob_track* scrob_create_track(const char *artist, const char *track_title, unsigned int utc_timestamp) {
    scrob_track *track = malloc(sizeof(scrob_track));
    if (!track) {
        return NULL;
    }
    track->artist = scrob_strdup(artist);
    track->title = scrob_strdup(track_title);
    track->album = NULL;
    track->timestamp = utc_timestamp;
    return track;
}

bool scrob_set_track_album(scrob_track *track, const char *album) {
    char *copy = scrob_strdup(album);
    if (!copy) {
        return false;
    }
    if (track->album) free(track->album);
    track->album = copy;
    return true;

}

bool scrob_set_track_artist(scrob_track *track, const char *artist) {
    char *copy = scrob_strdup(artist);
    if (!copy) {
        return false;
    }
    if (track->artist) free(track->artist);
    track->artist = copy;
    return true;
}

bool scrob_set_track_title(scrob_track *track, const char *title) {
    char *copy = scrob_strdup(title);
    if (!copy) {
        return false;
    }
    if (track->title) free(track->title);
    track->title = copy;
    return true;
}

bool scrob_set_track_timestamp(scrob_track *track, unsigned int utc_timestamp) {
    track->timestamp = utc_timestamp;
    return true;
}

void scrob_destroy_track(scrob_track *track) {
    if (track) {
        if (track->artist) free(track->artist);
        if (track->title) free(track->title);
        if (track->album) free(track->album);
        free(track);
    }
}