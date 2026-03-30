/* md5.h - header file for md5c.c
 */

/*
 * This file includes a derived work of the RSA Data Security, Inc.
 * MD5 Message-Digest Algorithm, adapted for libscrobbler.
 */

/* Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
rights reserved.

License to copy and use this software is granted provided that it
is identified as the "RSA Data Security, Inc. MD5 Message-Digest
Algorithm" in all material mentioning or referencing this software
or this function.

License is also granted to make and use derivative works provided
that such works are identified as "derived from the RSA Data
Security, Inc. MD5 Message-Digest Algorithm" in all material
mentioning or referencing the derived work.

RSA Data Security, Inc. makes no representations concerning either
the merchantability of this software or the suitability of this
software for any particular purpose. It is provided "as is"
without express or implied warranty of any kind.

These notices must be retained in any copies of any part of this
documentation and/or software.
 */

#ifndef SCROB_MD5_H
#define SCROB_MD5_H

#include <stddef.h>
#include <stdint.h>

/* MD5 context. */
typedef struct {
  uint32_t state[4];                                /* state (ABCD) */
  uint32_t count[2];     /* number of bits, modulo 2^64 (lsb first) */
  uint8_t buffer[64];                              /* input buffer */
} scrob_md5_ctx;

void scrob_md5_init(scrob_md5_ctx *context);
void scrob_md5_update(scrob_md5_ctx *context, const uint8_t *input, size_t input_len);
void scrob_md5_final(uint8_t digest[16], scrob_md5_ctx *context);

#endif /* SCROB_MD5_H */