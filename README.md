# libscrobbler

A small C library for authenticating with the Last.fm API and submitting scrobbles.

This project currently provides:
- Client authentication setup
- Auth workflow helpers (token, session key, auth URL)
- Simple one-call scrobble helper

## Project Layout

- `include/`: public headers
- `src/`: implementation files
- `main.c`: example harness program
- `CMakeLists.txt`: build configuration

## Requirements

- C compiler with C99 support
- CMake
- libcurl development package

On Debian/Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake libcurl4-openssl-dev
```

## Build

```bash
cmake -S . -B build
cmake --build build
```

## Running the Harness

Set your Last.fm credentials as environment variables:

```bash
export LASTFM_API_KEY="your_api_key"
export LASTFM_SHARED_SECRET="your_shared_secret"
export LASTFM_SESSION_KEY="your_session_key"
```

Then run:

```bash
./build/libscrobbler_harness
```

Notes:
- If `LASTFM_SESSION_KEY` is present and valid, auth flow is skipped.
- If not authenticated, the harness requests a token, asks you to open the browser for user auth, then exchanges token for a session key.

## Public API Overview

Core:
- `scrob_init`
- `scrob_is_initialized`
- `scrob_version`

Client setup:
- `scrob_create_client`
- `scrob_destroy_client`
- `scrob_set_client_api_key`
- `scrob_set_client_shared_secret`
- `scrob_set_client_session_key`

Auth workflow:
- `scrob_get_client_token`
- `scrob_get_auth_url`
- `scrob_get_session_key`

Scrobbling:
- `scrob_easy_scrobble`
- `scrob_create_track` and related track setters

See headers in `include/scrob.h`, `include/client.h`, `include/auth.h`, and `include/scrobble.h`.

## Minimal Usage Example

```c
#include <time.h>

#include "scrob.h"
#include "client.h"
#include "auth.h"
#include "scrobble.h"

int main(void) {
	if (!scrob_init()) {
		return 1;
	}

	scrob_client *client = scrob_create_client();
	if (!client) {
		return 1;
	}

	scrob_set_client_api_key(client, "<32-char-api-key>");
	scrob_set_client_shared_secret(client, "<32-char-shared-secret>");

	// Option A: use an existing session key
	scrob_set_client_session_key(client, "<32-char-session-key>");

	// Option B: interactive auth flow
	// scrob_get_client_token(client);
	// const char *auth_url = scrob_get_auth_url(client);
	// Open auth_url in browser, approve app, then:
	// scrob_get_session_key(client);

	unsigned int utc_ts = (unsigned int)time(NULL);
	int rc = scrob_easy_scrobble(client, "Carissa's Wierd", "Sympathy Bush", utc_ts);

	scrob_destroy_client(client);
	return rc;
}
```