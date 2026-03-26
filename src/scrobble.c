#include "scrobble.h"
#include "client.h"

struct scrob_track {
    char *artist;
    char *title;
    char *album;
    unsigned int timestamp;
};

static char* strdup(const char *s) {
    size_t len = strlen(s) + 1;
    char *copy = malloc(len);
    if (copy) {
        memcpy(copy, s, len);
    }
    return copy;
}

// interface with scrobble API
int scrob_scrobble_track(scrob_client *client, const scrob_track *track) {

}

int scrob_easy_scrobble(scrob_client *client, const char *artist, const char *track_title, unsigned int utc_timestamp) {

}

// scrob track struct
scrob_track* scrob_create_track(const char *artist, const char *track_title, unsigned int utc_timestamp) {
    scrob_track *track = malloc(sizeof(scrob_track));
    if (!track) {
        return NULL;
    }
    track->artist = strdup(artist);
    track->title = strdup(track_title);
    track->album = NULL;
    track->timestamp = utc_timestamp;
    return track;
}

bool scrob_set_track_album(scrob_track *track, const char *album) {
    char *copy = strdup(album);
    if (!copy) {
        return false;
    }
    if (track->album) free(track->album);
    track->album = copy;
    return true;

}

bool scrob_set_track_artist(scrob_track *track, const char *artist) {
    char *copy = strdup(artist);
    if (!copy) {
        return false;
    }
    if (track->artist) free(track->artist);
    track->artist = copy;
    return true;
}

bool scrob_set_track_title(scrob_track *track, const char *title) {
    char *copy = strdup(title);
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