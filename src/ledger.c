/* Translated from RATUM prime/src/ledger.rs and verify.rs ReplayGuard by iohzrd.
 * File-backed share window (no redb). Same split arithmetic.
 * Copyright (C) iohzrd and RATUM contributors
 * Copyright (C) Blockvase contributors (C translation)
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#include "prime.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#define PRIME_MAX_SHARES 131072
#define PRIME_MAX_REPLAY 65536
#define PRIME_MAX_SESSIONS 32
#define PRIME_MAX_IDENTS 4096
#define PRIME_MAX_OWED 256
#define PRIME_MAX_OWED_ENTS PRIME_MAX_SPLIT_OUTPUTS

typedef struct {
	uint64_t at;
	uint64_t difficulty;
	unsigned char hash[32];
	char identity[PRIME_MAX_IDENTITY];
	char tag[32];
} prime_share_row;

typedef struct {
	char identity[PRIME_MAX_IDENTITY];
	uint64_t work;
} prime_ident_work;

typedef struct {
	unsigned char token[PRIME_RESUME_TOKEN_LEN];
	unsigned char client_pk[32];
	uint8_t coinbaser_id;
	prime_abw abw;
	int used;
} prime_saved_session;

struct prime_pool {
	pthread_mutex_t mu;
	char path[512];
	uint64_t window;
	uint64_t min_payout;
	uint16_t fee_bps;
	uint64_t total_work;
	uint64_t cumulative_work;
	size_t nshares;
	size_t share_head;
	prime_share_row shares[PRIME_MAX_SHARES];
	size_t nidents;
	prime_ident_work idents[PRIME_MAX_IDENTS];
	size_t nreplay;
	size_t replay_head;
	unsigned char replay[PRIME_MAX_REPLAY][32];
	prime_saved_session sessions[PRIME_MAX_SESSIONS];
	uint32_t last_height;
	unsigned char last_block[32];
	char last_finder[PRIME_MAX_IDENTITY];
	uint64_t blocks_found;
	size_t nowed;
	struct {
		uint64_t at;
		uint32_t height;
		unsigned char hash[32];
		uint64_t total;
		uint64_t settled_at;
		char finder[PRIME_MAX_IDENTITY];
		size_t nent;
		char ents[PRIME_MAX_OWED_ENTS][PRIME_MAX_IDENTITY];
		uint64_t amounts[PRIME_MAX_OWED_ENTS];
	} owed[PRIME_MAX_OWED];
};

const char *prime_identity_of(const char *username, char *out, size_t out_len)
{
	size_t n = 0;
	if (!username) {
		username = "";
	}
	while (username[n] && username[n] != '.' && n + 1 < out_len) {
		n++;
	}
	if (n >= out_len) {
		n = out_len ? out_len - 1 : 0;
	}
	if (out && out_len) {
		memcpy(out, username, n);
		out[n] = 0;
	}
	return out;
}

uint64_t prime_window_for_difficulty(double network_diff, double multiple, uint64_t floor)
{
	double w = network_diff * multiple;
	uint64_t scaled;
	if (!(w >= 1.0) || w != w) {
		scaled = 1;
	} else if (w > (double)UINT64_MAX) {
		scaled = UINT64_MAX;
	} else {
		scaled = (uint64_t)w;
	}
	if (floor < 1) {
		floor = 1;
	}
	return scaled > floor ? scaled : floor;
}

static void ident_add(prime_pool *p, const char *identity, uint64_t diff, int add)
{
	size_t i;
	for (i = 0; i < p->nidents; i++) {
		if (strcmp(p->idents[i].identity, identity) == 0) {
			if (add) {
				p->idents[i].work += diff;
			} else if (p->idents[i].work >= diff) {
				p->idents[i].work -= diff;
			} else {
				p->idents[i].work = 0;
			}
			return;
		}
	}
	if (!add || p->nidents >= PRIME_MAX_IDENTS) {
		return;
	}
	snprintf(p->idents[p->nidents].identity, PRIME_MAX_IDENTITY, "%s", identity);
	p->idents[p->nidents].work = diff;
	p->nidents++;
}

static void drop_oldest(prime_pool *p)
{
	prime_share_row *s;
	if (!p->nshares) {
		return;
	}
	s = &p->shares[p->share_head];
	if (p->total_work >= s->difficulty) {
		p->total_work -= s->difficulty;
	} else {
		p->total_work = 0;
	}
	ident_add(p, s->identity, s->difficulty, 0);
	p->share_head = (p->share_head + 1) % PRIME_MAX_SHARES;
	p->nshares--;
}

static void trim(prime_pool *p)
{
	while (p->nshares > 1 && p->total_work > p->window) {
		uint64_t over = p->total_work - p->window;
		prime_share_row *s = &p->shares[p->share_head];
		if (s->difficulty > over) {
			break;
		}
		drop_oldest(p);
	}
	while (p->nshares > PRIME_MAX_SHARES) {
		drop_oldest(p);
	}
}

static int replay_has(prime_pool *p, const unsigned char hash[32])
{
	size_t i;
	for (i = 0; i < p->nreplay; i++) {
		if (memcmp(p->replay[i], hash, 32) == 0) {
			return 1;
		}
	}
	return 0;
}

static void replay_add(prime_pool *p, const unsigned char hash[32])
{
	if (p->nreplay < PRIME_MAX_REPLAY) {
		memcpy(p->replay[p->nreplay], hash, 32);
		p->nreplay++;
		return;
	}
	memcpy(p->replay[p->replay_head], hash, 32);
	p->replay_head = (p->replay_head + 1) % PRIME_MAX_REPLAY;
}

static void append_row(prime_pool *p, const prime_share_row *s)
{
	FILE *f;
	char path[600];
	snprintf(path, sizeof path, "%s.shares", p->path);
	f = fopen(path, "ab");
	if (!f) {
		return;
	}
	fwrite(s, sizeof *s, 1, f);
	fclose(f);
}

static void load_shares(prime_pool *p)
{
	FILE *f;
	prime_share_row s;
	char path[600];
	snprintf(path, sizeof path, "%s.shares", p->path);
	f = fopen(path, "rb");
	if (!f) {
		return;
	}
	while (fread(&s, sizeof s, 1, f) == 1) {
		if (p->nshares == PRIME_MAX_SHARES) {
			drop_oldest(p);
		}
		p->shares[(p->share_head + p->nshares) % PRIME_MAX_SHARES] = s;
		p->nshares++;
		p->total_work += s.difficulty;
		p->cumulative_work += s.difficulty;
		ident_add(p, s.identity, s.difficulty, 1);
		replay_add(p, s.hash);
	}
	fclose(f);
	trim(p);
}

static void load_sessions(prime_pool *p)
{
	FILE *f;
	char path[600];
	snprintf(path, sizeof path, "%s.sessions", p->path);
	f = fopen(path, "rb");
	if (!f) {
		return;
	}
	if (fread(p->sessions, sizeof p->sessions, 1, f) != 1) {
		memset(p->sessions, 0, sizeof p->sessions);
	}
	fclose(f);
}

static void save_sessions(prime_pool *p)
{
	FILE *f;
	char path[600];
	snprintf(path, sizeof path, "%s.sessions", p->path);
	f = fopen(path, "wb");
	if (!f) {
		return;
	}
	fwrite(p->sessions, sizeof p->sessions, 1, f);
	fclose(f);
	chmod(path, 0600);
}

static void load_owed(prime_pool *p)
{
	FILE *f;
	char path[600], line[512];
	snprintf(path, sizeof path, "%s.owed", p->path);
	f = fopen(path, "r");
	if (!f) {
		return;
	}
	while (fgets(line, sizeof line, f) && p->nowed < PRIME_MAX_OWED) {
		char hex[65];
		unsigned long height, nent;
		unsigned long long at, total, settled;
		if (sscanf(line, "%64s %lu %llu %llu %llu %lu", hex, &height, &at, &total, &settled,
			   &nent) != 6) {
			continue;
		}
		if (prime_hex_decode(hex, p->owed[p->nowed].hash, 32) != 0) {
			continue;
		}
		p->owed[p->nowed].height = (uint32_t)height;
		p->owed[p->nowed].at = at;
		p->owed[p->nowed].total = total;
		p->owed[p->nowed].settled_at = settled;
		p->owed[p->nowed].nent = 0;
		while (p->owed[p->nowed].nent < nent
		       && p->owed[p->nowed].nent < PRIME_MAX_OWED_ENTS
		       && fgets(line, sizeof line, f)) {
			char ident[PRIME_MAX_IDENTITY];
			unsigned long long sats;
			if (sscanf(line, " %127s %llu", ident, &sats) != 2) {
				break;
			}
			snprintf(p->owed[p->nowed].ents[p->owed[p->nowed].nent],
				 PRIME_MAX_IDENTITY, "%s", ident);
			p->owed[p->nowed].amounts[p->owed[p->nowed].nent] = sats;
			p->owed[p->nowed].nent++;
		}
		p->nowed++;
	}
	fclose(f);
}

static void save_owed(prime_pool *p)
{
	FILE *f;
	char path[600];
	size_t i, j;
	snprintf(path, sizeof path, "%s.owed", p->path);
	f = fopen(path, "w");
	if (!f) {
		return;
	}
	for (i = 0; i < p->nowed; i++) {
		char hex[65];
		prime_hex_encode(p->owed[i].hash, 32, hex, sizeof hex);
		fprintf(f, "%s %u %llu %llu %llu %zu\n", hex, p->owed[i].height,
			(unsigned long long)p->owed[i].at, (unsigned long long)p->owed[i].total,
			(unsigned long long)p->owed[i].settled_at, p->owed[i].nent);
		for (j = 0; j < p->owed[i].nent; j++) {
			fprintf(f, " %s %llu\n", p->owed[i].ents[j],
				(unsigned long long)p->owed[i].amounts[j]);
		}
	}
	fclose(f);
}

static void print_owed_row(FILE *out, const prime_pool *p, size_t i)
{
	char hex[65];
	size_t j;
	prime_hex_encode(p->owed[i].hash, 32, hex, sizeof hex);
	fprintf(out, "height %u block %s found %llu total %llu sats %s",
		p->owed[i].height, hex, (unsigned long long)p->owed[i].at,
		(unsigned long long)p->owed[i].total,
		p->owed[i].settled_at ? "settled" : "unsettled");
	if (p->owed[i].settled_at) {
		fprintf(out, " at %llu", (unsigned long long)p->owed[i].settled_at);
	}
	fputc('\n', out);
	for (j = 0; j < p->owed[i].nent; j++) {
		fprintf(out, "  %s %llu\n", p->owed[i].ents[j],
			(unsigned long long)p->owed[i].amounts[j]);
	}
}

prime_pool *prime_pool_open(const char *path, uint64_t window, uint64_t min_payout, uint16_t fee_bps)
{
	prime_pool *p = calloc(1, sizeof *p);
	if (!p) {
		return NULL;
	}
	pthread_mutex_init(&p->mu, NULL);
	snprintf(p->path, sizeof p->path, "%s", path ? path : "data/ledger");
	p->window = window ? window : 1;
	p->min_payout = min_payout;
	p->fee_bps = fee_bps > 100 ? 100 : fee_bps;
	load_shares(p);
	load_sessions(p);
	load_owed(p);
	fprintf(stderr, "prime: ledger %s shares=%zu work=%llu window=%llu owed=%zu\n",
		p->path, p->nshares, (unsigned long long)p->total_work,
		(unsigned long long)p->window, p->nowed);
	return p;
}

void prime_pool_close(prime_pool *p)
{
	if (!p) {
		return;
	}
	pthread_mutex_destroy(&p->mu);
	free(p);
}

void prime_pool_set_window(prime_pool *p, uint64_t window)
{
	if (!p) {
		return;
	}
	pthread_mutex_lock(&p->mu);
	p->window = window ? window : 1;
	trim(p);
	pthread_mutex_unlock(&p->mu);
}

int prime_pool_record_share(prime_pool *p, const char *identity, uint64_t difficulty,
			    const unsigned char hash[32], const char *tag)
{
	prime_share_row s;
	if (!p || !identity || !hash || !difficulty) {
		return -1;
	}
	memset(&s, 0, sizeof s);
	s.at = (uint64_t)time(NULL);
	s.difficulty = difficulty;
	memcpy(s.hash, hash, 32);
	snprintf(s.identity, sizeof s.identity, "%s", identity);
	snprintf(s.tag, sizeof s.tag, "%s", tag ? tag : "");
	pthread_mutex_lock(&p->mu);
	if (p->nshares == PRIME_MAX_SHARES) {
		drop_oldest(p);
	}
	p->shares[(p->share_head + p->nshares) % PRIME_MAX_SHARES] = s;
	p->nshares++;
	p->total_work += difficulty;
	p->cumulative_work += difficulty;
	ident_add(p, identity, difficulty, 1);
	trim(p);
	append_row(p, &s);
	pthread_mutex_unlock(&p->mu);
	return 0;
}

int prime_pool_replay_new(prime_pool *p, const unsigned char hash[32])
{
	int ok;
	if (!p || !hash) {
		return 1;
	}
	pthread_mutex_lock(&p->mu);
	if (replay_has(p, hash)) {
		ok = 0;
	} else {
		replay_add(p, hash);
		ok = 1;
	}
	pthread_mutex_unlock(&p->mu);
	return ok;
}

void prime_pool_replay_forget(prime_pool *p, const unsigned char hash[32])
{
	size_t i;
	if (!p || !hash) {
		return;
	}
	pthread_mutex_lock(&p->mu);
	for (i = 0; i < p->nreplay; i++) {
		if (memcmp(p->replay[i], hash, 32) == 0) {
			memset(p->replay[i], 0, 32);
			break;
		}
	}
	pthread_mutex_unlock(&p->mu);
}

static int cmp_ident_desc(const void *a, const void *b)
{
	const prime_ident_work *x = a, *y = b;
	if (x->work < y->work) {
		return 1;
	}
	if (x->work > y->work) {
		return -1;
	}
	return strcmp(x->identity, y->identity);
}

static void json_escape_append(char **cur, size_t *left, const char *s)
{
	if (!cur || !*cur || !left || !*left) {
		return;
	}
	for (; s && *s && *left > 1; s++) {
		unsigned char c = (unsigned char)*s;
		if ((c == '"' || c == '\\') && *left > 2) {
			*(*cur)++ = '\\';
			*(*cur)++ = (char)c;
			*left -= 2;
		} else if (c >= 0x20 && c < 0x7f) {
			*(*cur)++ = (char)c;
			(*left)--;
		}
	}
	if (*left) {
		**cur = 0;
	}
}

size_t prime_pool_split(prime_pool *p, uint64_t value, char idents[][PRIME_MAX_IDENTITY],
			uint64_t *amounts, size_t max_n)
{
	prime_ident_work kept[PRIME_MAX_IDENTS];
	size_t n = 0, i;
	uint64_t miners, work = 0, left, min_payout;
	uint16_t fee;

	if (!p || !idents || !amounts || !max_n) {
		return 0;
	}
	pthread_mutex_lock(&p->mu);
	fee = p->fee_bps;
	min_payout = p->min_payout;
	miners = value - (uint64_t)((unsigned __int128)value * fee / 10000);
	if (!p->total_work || !miners) {
		pthread_mutex_unlock(&p->mu);
		return 0;
	}
	n = p->nidents;
	if (n > PRIME_MAX_IDENTS) {
		n = PRIME_MAX_IDENTS;
	}
	memcpy(kept, p->idents, n * sizeof kept[0]);
	pthread_mutex_unlock(&p->mu);

	qsort(kept, n, sizeof kept[0], cmp_ident_desc);
	if (n > max_n) {
		n = max_n;
	}
	if (n > PRIME_MAX_COINBASER_OUTPUTS) {
		n = PRIME_MAX_COINBASER_OUTPUTS;
	}
	for (i = 0; i < n; i++) {
		work += kept[i].work;
	}
	while (n) {
		uint64_t w = kept[n - 1].work;
		if (!work) {
			n = 0;
			break;
		}
		if ((uint64_t)((unsigned __int128)miners * w / work) >= min_payout) {
			break;
		}
		work -= w;
		n--;
	}
	left = miners;
	for (i = 0; i < n; i++) {
		uint64_t amount;
		if (!work) {
			break;
		}
		amount = (uint64_t)((unsigned __int128)left * kept[i].work / work);
		left -= amount;
		work -= kept[i].work;
		if (!amount) {
			continue;
		}
		snprintf(idents[i], PRIME_MAX_IDENTITY, "%s", kept[i].identity);
		amounts[i] = amount;
	}
	return i;
}

int prime_pool_record_block(prime_pool *p, uint32_t height, const unsigned char hash[32],
			    const char *finder, uint64_t paid_split, uint64_t paid_pool)
{
	FILE *f;
	char path[600];
	if (!p) {
		return -1;
	}
	pthread_mutex_lock(&p->mu);
	p->last_height = height;
	memcpy(p->last_block, hash, 32);
	snprintf(p->last_finder, sizeof p->last_finder, "%s", finder ? finder : "");
	p->blocks_found++;
	pthread_mutex_unlock(&p->mu);
	snprintf(path, sizeof path, "%s.blocks", p->path);
	f = fopen(path, "a");
	if (f) {
		char hex[65];
		prime_hex_encode(hash, 32, hex, sizeof hex);
		fprintf(f, "%u %s %s split=%llu pool=%llu\n", height, hex, finder ? finder : "",
			(unsigned long long)paid_split, (unsigned long long)paid_pool);
		fclose(f);
	}
	return 0;
}

int prime_pool_stats_json(prime_pool *p, char *out, size_t out_len)
{
	size_t i, n;
	int w;
	char *cur;
	size_t left;
	prime_ident_work snap[64];
	uint64_t total, shares, blocks, window;
	if (!p || !out || out_len < 32) {
		return -1;
	}
	pthread_mutex_lock(&p->mu);
	total = p->total_work;
	shares = p->nshares;
	blocks = p->blocks_found;
	window = p->window;
	n = p->nidents < 64 ? p->nidents : 64;
	memcpy(snap, p->idents, n * sizeof snap[0]);
	pthread_mutex_unlock(&p->mu);
	qsort(snap, n, sizeof snap[0], cmp_ident_desc);
	cur = out;
	left = out_len;
	w = snprintf(cur, left,
		     "{\"shares\":%llu,\"work\":%llu,\"window\":%llu,\"blocks\":%llu,\"miners\":[",
		     (unsigned long long)shares, (unsigned long long)total,
		     (unsigned long long)window, (unsigned long long)blocks);
	if (w < 0 || (size_t)w >= left) {
		return -1;
	}
	cur += w;
	left -= (size_t)w;
	for (i = 0; i < n; i++) {
		double pct = total ? ((double)snap[i].work * 100.0 / (double)total) : 0.0;
		w = snprintf(cur, left, "%s{\"id\":\"", i ? "," : "");
		if (w < 0 || (size_t)w >= left) {
			break;
		}
		cur += w;
		left -= (size_t)w;
		json_escape_append(&cur, &left, snap[i].identity);
		w = snprintf(cur, left, "\",\"work\":%llu,\"window_percent\":%.6f}",
			     (unsigned long long)snap[i].work, pct);
		if (w < 0 || (size_t)w >= left) {
			break;
		}
		cur += w;
		left -= (size_t)w;
	}
	if (left < 3) {
		return -1;
	}
	memcpy(cur, "]}", 3);
	return 0;
}

uint64_t prime_pool_share_count(const prime_pool *p)
{
	return p ? p->nshares : 0;
}

uint64_t prime_pool_total_work(const prime_pool *p)
{
	return p ? p->total_work : 0;
}

uint64_t prime_pool_window(const prime_pool *p)
{
	return p ? p->window : 0;
}

uint64_t prime_pool_blocks_found(const prime_pool *p)
{
	return p ? p->blocks_found : 0;
}

int prime_pool_resume_put(prime_pool *p, const unsigned char token[PRIME_RESUME_TOKEN_LEN],
			  const unsigned char client_pk[32], uint8_t coinbaser_id,
			  const prime_abw *abw)
{
	int i, slot = -1;
	if (!p || !token || !client_pk) {
		return -1;
	}
	pthread_mutex_lock(&p->mu);
	for (i = 0; i < PRIME_MAX_SESSIONS; i++) {
		if (p->sessions[i].used && memcmp(p->sessions[i].token, token, PRIME_RESUME_TOKEN_LEN) == 0
		    && memcmp(p->sessions[i].client_pk, client_pk, 32) == 0) {
			slot = i;
			break;
		}
		if (!p->sessions[i].used && slot < 0) {
			slot = i;
		}
	}
	if (slot < 0) {
		slot = 0;
	}
	memcpy(p->sessions[slot].token, token, PRIME_RESUME_TOKEN_LEN);
	memcpy(p->sessions[slot].client_pk, client_pk, 32);
	p->sessions[slot].coinbaser_id = coinbaser_id;
	if (abw) {
		p->sessions[slot].abw = *abw;
	}
	p->sessions[slot].used = 1;
	save_sessions(p);
	pthread_mutex_unlock(&p->mu);
	return 0;
}

int prime_pool_resume_get(prime_pool *p, const unsigned char token[PRIME_RESUME_TOKEN_LEN],
			  const unsigned char client_pk[32], uint8_t *coinbaser_id,
			  prime_abw *abw)
{
	int i, found = 0;
	if (!p || !token || !client_pk) {
		return 0;
	}
	pthread_mutex_lock(&p->mu);
	for (i = 0; i < PRIME_MAX_SESSIONS; i++) {
		if (p->sessions[i].used && memcmp(p->sessions[i].token, token, PRIME_RESUME_TOKEN_LEN) == 0
		    && memcmp(p->sessions[i].client_pk, client_pk, 32) == 0) {
			if (coinbaser_id) {
				*coinbaser_id = p->sessions[i].coinbaser_id;
			}
			if (abw) {
				*abw = p->sessions[i].abw;
			}
			found = 1;
			break;
		}
	}
	pthread_mutex_unlock(&p->mu);
	return found;
}

int prime_pool_record_owed(prime_pool *p, uint32_t height, const unsigned char hash[32],
			   const char *finder, uint64_t total,
			   const char idents[][PRIME_MAX_IDENTITY], const uint64_t *amounts,
			   size_t n)
{
	size_t i, slot;
	if (!p || !hash || !n || !idents || !amounts) {
		return -1;
	}
	pthread_mutex_lock(&p->mu);
	for (i = 0; i < p->nowed; i++) {
		if (memcmp(p->owed[i].hash, hash, 32) == 0) {
			pthread_mutex_unlock(&p->mu);
			return 0;
		}
	}
	if (p->nowed == PRIME_MAX_OWED) {
		memmove(&p->owed[0], &p->owed[1], (PRIME_MAX_OWED - 1) * sizeof p->owed[0]);
		p->nowed--;
	}
	slot = p->nowed++;
	memset(&p->owed[slot], 0, sizeof p->owed[slot]);
	p->owed[slot].at = (uint64_t)time(NULL);
	p->owed[slot].height = height;
	memcpy(p->owed[slot].hash, hash, 32);
	p->owed[slot].total = total;
	snprintf(p->owed[slot].finder, sizeof p->owed[slot].finder, "%s", finder ? finder : "");
	if (n > PRIME_MAX_OWED_ENTS) {
		n = PRIME_MAX_OWED_ENTS;
	}
	p->owed[slot].nent = n;
	for (i = 0; i < n; i++) {
		snprintf(p->owed[slot].ents[i], PRIME_MAX_IDENTITY, "%s", idents[i]);
		p->owed[slot].amounts[i] = amounts[i];
	}
	save_owed(p);
	pthread_mutex_unlock(&p->mu);
	return 0;
}

int prime_pool_settle(prime_pool *p, const unsigned char hash[32], uint64_t at)
{
	size_t i;
	if (!p || !hash) {
		return -1;
	}
	pthread_mutex_lock(&p->mu);
	for (i = 0; i < p->nowed; i++) {
		if (memcmp(p->owed[i].hash, hash, 32) == 0) {
			if (!p->owed[i].settled_at) {
				p->owed[i].settled_at = at ? at : 1;
				save_owed(p);
			}
			print_owed_row(stdout, p, i);
			pthread_mutex_unlock(&p->mu);
			return 0;
		}
	}
	pthread_mutex_unlock(&p->mu);
	return 1;
}

int prime_pool_void_owed(prime_pool *p, const unsigned char hash[32])
{
	size_t i;
	if (!p || !hash) {
		return -1;
	}
	pthread_mutex_lock(&p->mu);
	for (i = 0; i < p->nowed; i++) {
		if (memcmp(p->owed[i].hash, hash, 32) == 0) {
			print_owed_row(stdout, p, i);
			if (i + 1 < p->nowed) {
				memmove(&p->owed[i], &p->owed[i + 1],
					(p->nowed - i - 1) * sizeof p->owed[0]);
			}
			p->nowed--;
			save_owed(p);
			pthread_mutex_unlock(&p->mu);
			return 0;
		}
	}
	pthread_mutex_unlock(&p->mu);
	return 1;
}

int prime_pool_list_owed(prime_pool *p, FILE *out)
{
	size_t i;
	if (!p || !out) {
		return -1;
	}
	pthread_mutex_lock(&p->mu);
	if (!p->nowed) {
		fprintf(out, "no owed blocks\n");
	}
	for (i = 0; i < p->nowed; i++) {
		print_owed_row(out, p, i);
	}
	pthread_mutex_unlock(&p->mu);
	return 0;
}

int prime_pool_dump(prime_pool *p, FILE *out)
{
	size_t i, idx;
	if (!p || !out) {
		return -1;
	}
	pthread_mutex_lock(&p->mu);
	fprintf(out, "shares %zu work %llu window %llu blocks %llu owed %zu\n",
		p->nshares, (unsigned long long)p->total_work, (unsigned long long)p->window,
		(unsigned long long)p->blocks_found, p->nowed);
	for (i = 0; i < p->nshares; i++) {
		char hex[65];
		idx = (p->share_head + i) % PRIME_MAX_SHARES;
		prime_hex_encode(p->shares[idx].hash, 32, hex, sizeof hex);
		fprintf(out, "%llu %llu %s %s\n", (unsigned long long)p->shares[idx].at,
			(unsigned long long)p->shares[idx].difficulty, p->shares[idx].identity,
			hex);
	}
	for (i = 0; i < p->nowed; i++) {
		print_owed_row(out, p, i);
	}
	pthread_mutex_unlock(&p->mu);
	return 0;
}
