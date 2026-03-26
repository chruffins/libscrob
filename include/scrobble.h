#ifndef SCROB_SCROBBLE_H
#define SCROB_SCROBBLE_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct scrob_track scrob_track;
typedef struct scrob_client scrob_client;

// interface with scrobble API
int scrob_scrobble_track(scrob_client *client, const scrob_track *track);
int scrob_easy_scrobble(scrob_client *client, const char *artist, const char *track_title, unsigned int utc_timestamp);

// scrob track struct
scrob_track* scrob_create_track(const char *artist, const char *track_title, unsigned int utc_timestamp);
bool scrob_set_track_album(scrob_track *track, const char *album);
bool scrob_set_track_artist(scrob_track *track, const char *artist);
bool scrob_set_track_title(scrob_track *track, const char *title);
bool scrob_set_track_timestamp(scrob_track *track, unsigned int utc_timestamp);

void scrob_destroy_track(scrob_track *track);

#ifdef __cplusplus
}
#endif

#endif