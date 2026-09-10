/* bitcoin-cli helpers. Knots v29 bitcoin-cli on this box rejects a separate
 * `-datadir PATH` argv (Method not found); `-datadir=PATH` works.
 * Copyright (C) Blockvase contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#define _POSIX_C_SOURCE 200809L
#include "prime.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int prime_rpc_datadir_arg(const char *datadir, char *out, size_t out_len)
{
	int n;
	if (!datadir || !datadir[0] || !out || out_len < 16) {
		return -1;
	}
	n = snprintf(out, out_len, "-datadir=%s", datadir);
	if (n < 0 || (size_t)n >= out_len) {
		return -1;
	}
	return 0;
}

int prime_rpc_call(const char *datadir, const char *rest, char *out, size_t out_len)
{
	char cmd[768];
	char darg[600];
	FILE *fp;
	size_t n;
	if (!rest || !out || !out_len) {
		return -1;
	}
	out[0] = 0;
	if (prime_rpc_datadir_arg(datadir, darg, sizeof darg) != 0) {
		return -1;
	}
	if (snprintf(cmd, sizeof cmd, "bitcoin-cli %s %s 2>/dev/null", darg, rest) >= (int)sizeof cmd) {
		return -1;
	}
	fp = popen(cmd, "r");
	if (!fp) {
		return -1;
	}
	n = fread(out, 1, out_len - 1, fp);
	out[n] = 0;
	if (pclose(fp) != 0) {
		return -1;
	}
	while (n && (out[n - 1] == '\n' || out[n - 1] == '\r' || out[n - 1] == ' ')) {
		out[--n] = 0;
	}
	return 0;
}

int prime_rpc_difficulty(const char *datadir, double *out)
{
	char line[128];
	double d;
	if (!out) {
		return -1;
	}
	if (prime_rpc_call(datadir, "getdifficulty", line, sizeof line) != 0) {
		return -1;
	}
	d = strtod(line, NULL);
	if (!(d > 0)) {
		return -1;
	}
	*out = d;
	return 0;
}

int prime_rpc_networkhashps(const char *datadir, unsigned blocks, double *out)
{
	char rest[64];
	char line[128];
	double d;
	if (!out) {
		return -1;
	}
	if (snprintf(rest, sizeof rest, "getnetworkhashps %u", blocks ? blocks : 120) >= (int)sizeof rest) {
		return -1;
	}
	if (prime_rpc_call(datadir, rest, line, sizeof line) != 0) {
		return -1;
	}
	d = strtod(line, NULL);
	if (!(d > 0)) {
		return -1;
	}
	*out = d;
	return 0;
}

int prime_rpc_lookback_since(const char *datadir, unsigned blocks, uint64_t *since)
{
	char count_s[32];
	char rest[96];
	char hash[80];
	char hdr[4096];
	const char *p, *colon;
	char *end;
	long height, start;
	unsigned long t;
	if (!since) {
		return -1;
	}
	if (prime_rpc_call(datadir, "getblockcount", count_s, sizeof count_s) != 0) {
		return -1;
	}
	height = strtol(count_s, NULL, 10);
	if (height < 0) {
		return -1;
	}
	if (!blocks) {
		blocks = PRIME_NETHASH_BLOCKS;
	}
	start = height - (long)blocks + 1;
	if (start < 0) {
		start = 0;
	}
	if (snprintf(rest, sizeof rest, "getblockhash %ld", start) >= (int)sizeof rest) {
		return -1;
	}
	if (prime_rpc_call(datadir, rest, hash, sizeof hash) != 0 || !hash[0]) {
		return -1;
	}
	if (snprintf(rest, sizeof rest, "getblockheader %s", hash) >= (int)sizeof rest) {
		return -1;
	}
	if (prime_rpc_call(datadir, rest, hdr, sizeof hdr) != 0) {
		return -1;
	}
	p = strstr(hdr, "\"time\":");
	if (!p) {
		return -1;
	}
	colon = strchr(p, ':');
	if (!colon) {
		return -1;
	}
	t = strtoul(colon + 1, &end, 10);
	if (end == colon + 1 || !t) {
		return -1;
	}
	*since = (uint64_t)t;
	return 0;
}

int prime_parent_have(const char *datadir, const unsigned char prev_hash[32])
{
	unsigned char rev[32];
	char hex[65];
	char rest[96];
	char ignore[8];
	int i;
	if (!datadir || !prev_hash) {
		return 0;
	}
	for (i = 0; i < 32; i++) {
		rev[i] = prev_hash[31 - i];
	}
	if (prime_hex_encode(rev, 32, hex, sizeof hex) != 0) {
		return 0;
	}
	if (snprintf(rest, sizeof rest, "getblockheader %s", hex) >= (int)sizeof rest) {
		return 0;
	}
	return prime_rpc_call(datadir, rest, ignore, sizeof ignore) == 0;
}

int prime_submit_raw_block(const char *datadir, const unsigned char *block, size_t block_len)
{
	prime_config_opts opt;
	unsigned char z[32];
	memset(&opt, 0, sizeof opt);
	opt.bitcoin_datadir = datadir;
	memset(z, 0, sizeof z);
	return prime_submit_block(&opt, block, block_len, z);
}

typedef struct {
	prime_pool *pool;
	char datadir[512];
	double multiple;
	uint64_t floor;
} tip_arg;

static void *tip_thread(void *arg)
{
	tip_arg *a = arg;
	char last_hash[80];
	double last_d = 0;
	last_hash[0] = 0;
	while (a && a->pool) {
		double d = 0;
		char hash[80];
		sleep(30);
		if (prime_rpc_difficulty(a->datadir, &d) == 0 && d > 0) {
			uint64_t win = prime_window_for_difficulty(d, a->multiple, a->floor);
			prime_pool_set_window(a->pool, win);
			if (d != last_d) {
				fprintf(stderr, "prime: network difficulty %.2f window %llu\n",
					d, (unsigned long long)win);
				last_d = d;
			}
		}
		if (prime_rpc_call(a->datadir, "getbestblockhash", hash, sizeof hash) == 0
		    && hash[0] && strcmp(hash, last_hash) != 0) {
			fprintf(stderr, "prime: node tip %s\n", hash);
			snprintf(last_hash, sizeof last_hash, "%s", hash);
		}
	}
	free(a);
	return NULL;
}

int prime_tip_start(const char *datadir, prime_pool *pool, double multiple, uint64_t floor)
{
	tip_arg *a;
	pthread_t th;
	double d = 0;
	if (!datadir || !datadir[0] || !pool) {
		return -1;
	}
	if (prime_rpc_difficulty(datadir, &d) == 0 && d > 0) {
		uint64_t win = prime_window_for_difficulty(d, multiple, floor);
		prime_pool_set_window(pool, win);
		fprintf(stderr, "prime: network difficulty %.2f window %llu\n",
			d, (unsigned long long)win);
	} else {
		fprintf(stderr,
			"prime: could not read getdifficulty; keeping loaded shares until RPC is up\n");
	}
	a = calloc(1, sizeof *a);
	if (!a) {
		return -1;
	}
	snprintf(a->datadir, sizeof a->datadir, "%s", datadir);
	a->pool = pool;
	a->multiple = multiple;
	a->floor = floor;
	if (pthread_create(&th, NULL, tip_thread, a) != 0) {
		free(a);
		return -1;
	}
	pthread_detach(th);
	return 0;
}
