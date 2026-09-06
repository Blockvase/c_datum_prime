/* Translated from RATUM core/src/datum/handshake.rs KeyPairs by iohzrd.
 * Copyright (C) iohzrd and RATUM contributors
 * Copyright (C) Blockvase contributors (C translation)
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#define _POSIX_C_SOURCE 200809L
#include "prime.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int prime_keys_generate(prime_keypairs *k)
{
	if (crypto_sign_keypair(k->sign_pk, k->sign_sk) != 0) {
		return -1;
	}
	if (crypto_box_keypair(k->box_pk, k->box_sk) != 0) {
		return -1;
	}
	return 0;
}

void prime_keys_pubkey_hex(const prime_keypairs *k, char out[129])
{
	unsigned char both[64];
	memcpy(both, k->sign_pk, 32);
	memcpy(both + 32, k->box_pk, 32);
	prime_hex_encode(both, 64, out, 129);
}

static int write_keys(const char *path, const prime_keypairs *k)
{
	FILE *f;
	char sign_hex[crypto_sign_SECRETKEYBYTES * 2 + 1];
	char box_hex[crypto_box_SECRETKEYBYTES * 2 + 1];
	int fd;

	if (prime_hex_encode(k->sign_sk, crypto_sign_SECRETKEYBYTES, sign_hex, sizeof sign_hex) != 0) {
		return -1;
	}
	if (prime_hex_encode(k->box_sk, crypto_box_SECRETKEYBYTES, box_hex, sizeof box_hex) != 0) {
		return -1;
	}

	f = fopen(path, "w");
	if (!f) {
		return -1;
	}
	fd = fileno(f);
	if (fd >= 0) {
		(void)fchmod(fd, 0600);
	}
	if (fprintf(f, "# c-datum-prime pool secret keys. keep private.\n") < 0)
	    || fprintf(f, "sign_sk=%s\n", sign_hex) < 0
	    || fprintf(f, "box_sk=%s\n", box_hex) < 0) {
		fclose(f);
		return -1;
	}
	if (fclose(f) != 0) {
		return -1;
	}
	sodium_memzero(sign_hex, sizeof sign_hex);
	sodium_memzero(box_hex, sizeof box_hex);
	return 0;
}

static int load_keys(const char *path, prime_keypairs *k)
{
	FILE *f = fopen(path, "r");
	char line[512];
	int got_sign = 0;
	int got_box = 0;

	if (!f) {
		return -1;
	}
	memset(k, 0, sizeof *k);
	while (fgets(line, sizeof line, f)) {
		if (strncmp(line, "sign_sk=", 8) == 0) {
			char *hex = line + 8;
			char *nl = strchr(hex, '\n');
			if (nl) {
				*nl = 0;
			}
			if (prime_hex_decode(hex, k->sign_sk, crypto_sign_SECRETKEYBYTES) != 0) {
				fclose(f);
				return -1;
			}
			got_sign = 1;
		} else if (strncmp(line, "box_sk=", 7) == 0) {
			char *hex = line + 7;
			char *nl = strchr(hex, '\n');
			if (nl) {
				*nl = 0;
			}
			if (prime_hex_decode(hex, k->box_sk, crypto_box_SECRETKEYBYTES) != 0) {
				fclose(f);
				return -1;
			}
			got_box = 1;
		}
	}
	fclose(f);
	if (!got_sign || !got_box) {
		return -1;
	}
	memcpy(k->sign_pk, k->sign_sk + 32, crypto_sign_PUBLICKEYBYTES);
	if (crypto_scalarmult_base(k->box_pk, k->box_sk) != 0) {
		return -1;
	}
	return 0;
}

static int ensure_parent_dir(const char *path)
{
	char dir[512];
	char *slash;
	size_t n = strlen(path);
	if (n >= sizeof dir) {
		return -1;
	}
	memcpy(dir, path, n + 1);
	slash = strrchr(dir, '/');
	if (!slash || slash == dir) {
		return 0;
	}
	*slash = 0;
	if (mkdir(dir, 0700) != 0 && errno != EEXIST) {
		return -1;
	}
	return 0;
}

int prime_keys_load_or_create(const char *path, prime_keypairs *k)
{
	if (access(path, F_OK) == 0) {
		return load_keys(path, k);
	}
	if (ensure_parent_dir(path) != 0) {
		return -1;
	}
	if (prime_keys_generate(k) != 0) {
		return -1;
	}
	return write_keys(path, k);
}
