#ifndef SCROB_H
#define SCROB_H

#include <stdbool.h>

#ifdef __cplusplus
    extern "C" {
#endif

bool scrob_init(void);

bool scrob_is_initialized(void);

const char* scrob_version(void);

#ifdef __cplusplus
    }
#endif

#endif /* SCROB_H */
