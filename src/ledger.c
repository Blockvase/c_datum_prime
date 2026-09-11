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
#define PRIME_MAX_EMPTY 32

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
	uint64_t public_work;
} prime_ident_work;

static int share_tag_is_sv1(const char *tag)
{
	return tag && strcmp(tag, PRIME_SV1_TAG) == 0;
}

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
	int have_window;
	uint64_t min_payout;
	uint16_t fee_bps;
	uint16_t fee_after_first_bps;
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
	size_t nempty;
	struct {
		uint64_t at;
		uint32_t height;
		unsigned char hash[32];
		uint64_t value;
		uint64_t total_work;
		uint64_t settled_at;
		char finder[PRIME_MAX_IDENTITY];
		size_t n;
		char idents[PRIME_MAX_IDENTS][PRIME_MAX_IDENTITY];
		uint64_t work[PRIME_MAX_IDENTS];
		uint64_t public_work[PRIME_MAX_IDENTS];
		uint16_t fee_bps;
		uint64_t min_payout;
		int pending;
	} empty[PRIME_MAX_EMPTY];
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

static void ident_add(prime_pool *p, const char *identity, uint64_t diff, int add, int is_public)
{
	size_t i;
	for (i = 0; i < p->nidents; i++) {
		if (strcmp(p->idents[i].identity, identity) == 0) {
			if (add) {
				p->idents[i].work += diff;
				if (is_public) {
					p->idents[i].public_work += diff;
				}
			} else {
				if (p->idents[i].work >= diff) {
					p->idents[i].work -= diff;
				} else {
					p->idents[i].work = 0;
				}
				if (is_public) {
					if (p->idents[i].public_work >= diff) {
						p->idents[i].public_work -= diff;
					} else {
						p->idents[i].public_work = 0;
					}
				}
			}
			return;
		}
	}
	if (!add || p->nidents >= PRIME_MAX_IDENTS) {
		return;
	}
	snprintf(p->idents[p->nidents].identity, PRIME_MAX_IDENTITY, "%s", identity);
	p->idents[p->nidents].work = diff;
	p->idents[p->nidents].public_work = is_public ? diff : 0;
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
	ident_add(p, s->identity, s->difficulty, 0, share_tag_is_sv1(s->tag));
	p->share_head = (p->share_head + 1) % PRIME_MAX_SHARES;
	p->nshares--;
}

static void trim(prime_pool *p)
{
	if (p->have_window) {
		while (p->nshares > 1 && p->total_work > p->window) {
			uint64_t over = p->total_work - p->window;
			prime_share_row *s = &p->shares[p->share_head];
			if (s->difficulty > over) {
				break;
			}
			drop_oldest(p);
		}
	}
	while (p->nshares > PRIME_MAX_SHARES) {
		drop_oldest(p);
	}
}

static void save_window(prime_pool *p)
{
	FILE *f;
	char path[600], tmp[608];

	if (!p->have_window) {
		return;
	}
	snprintf(path, sizeof path, "%s.window", p->path);
	snprintf(tmp, sizeof tmp, "%s.window.tmp", p->path);
	f = fopen(tmp, "w");
	if (!f) {
		return;
	}
	fprintf(f, "%llu\n", (unsigned long long)p->window);
	if (fclose(f) != 0) {
		remove(tmp);
		return;
	}
	if (rename(tmp, path) != 0) {
		remove(tmp);
	}
}

static int load_window(prime_pool *p)
{
	FILE *f;
	char path[600];
	unsigned long long w = 0;

	snprintf(path, sizeof path, "%s.window", p->path);
	f = fopen(path, "r");
	if (!f) {
		return 0;
	}
	if (fscanf(f, "%llu", &w) != 1 || w < 1) {
		fclose(f);
		return 0;
	}
	fclose(f);
	p->window = (uint64_t)w;
	p->have_window = 1;
	return 1;
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
		if (!s.at || !s.difficulty) {
			continue;
		}
		if (p->nshares == PRIME_MAX_SHARES) {
			drop_oldest(p);
		}
		p->shares[(p->share_head + p->nshares) % PRIME_MAX_SHARES] = s;
		p->nshares++;
		p->total_work += s.difficulty;
		p->cumulative_work += s.difficulty;
		ident_add(p, s.identity, s.difficulty, 1, share_tag_is_sv1(s.tag));
		replay_add(p, s.hash);
	}
	fclose(f);
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

static void save_empty(prime_pool *p)
{
	FILE *f;
	char path[600];
	size_t i, j;

	snprintf(path, sizeof path, "%s.empty", p->path);
	f = fopen(path, "w");
	if (!f) {
		return;
	}
	for (i = 0; i < p->nempty; i++) {
		char hex[65];
		if (p->empty[i].pending) {
			continue;
		}
		prime_hex_encode(p->empty[i].hash, 32, hex, sizeof hex);
		fprintf(f, "%s %u %llu %llu %llu %zu %llu %s %u %llu\n", hex, p->empty[i].height,
			(unsigned long long)p->empty[i].at,
			(unsigned long long)p->empty[i].value,
			(unsigned long long)p->empty[i].total_work, p->empty[i].n,
			(unsigned long long)p->empty[i].settled_at,
			p->empty[i].finder[0] ? p->empty[i].finder : "-",
			(unsigned)p->empty[i].fee_bps,
			(unsigned long long)p->empty[i].min_payout);
		for (j = 0; j < p->empty[i].n; j++) {
			fprintf(f, " %s %llu %llu\n", p->empty[i].idents[j],
				(unsigned long long)p->empty[i].work[j],
				(unsigned long long)p->empty[i].public_work[j]);
		}
	}
	fclose(f);
}

static void load_empty(prime_pool *p)
{
	FILE *f;
	char path[600], line[640];

	snprintf(path, sizeof path, "%s.empty", p->path);
	f = fopen(path, "r");
	if (!f) {
		return;
	}
	while (fgets(line, sizeof line, f) && p->nempty < PRIME_MAX_EMPTY) {
		char hex[65], finder[PRIME_MAX_IDENTITY];
		unsigned height = 0, fee = 0;
		unsigned long long at = 0, value = 0, total_work = 0, settled = 0, minp = 0;
		size_t nent = 0, j;
		int nfield;
		if (line[0] == ' ') {
			continue;
		}
		finder[0] = 0;
		nfield = sscanf(line, "%64s %u %llu %llu %llu %zu %llu %127s %u %llu", hex, &height,
				&at, &value, &total_work, &nent, &settled, finder, &fee, &minp);
		if (nfield < 7) {
			continue;
		}
		memset(&p->empty[p->nempty], 0, sizeof p->empty[p->nempty]);
		if (prime_hex_decode(hex, p->empty[p->nempty].hash, 32) != 0) {
			continue;
		}
		p->empty[p->nempty].height = (uint32_t)height;
		p->empty[p->nempty].at = at;
		p->empty[p->nempty].value = value;
		p->empty[p->nempty].total_work = total_work;
		p->empty[p->nempty].settled_at = settled;
		p->empty[p->nempty].fee_bps = nfield >= 9 ? (uint16_t)fee : 0;
		p->empty[p->nempty].min_payout = nfield >= 10 ? minp : p->min_payout;
		if (nfield >= 8 && finder[0] && strcmp(finder, "-") != 0) {
			snprintf(p->empty[p->nempty].finder, sizeof p->empty[p->nempty].finder,
				 "%s", finder);
		}
		if (nent > PRIME_MAX_IDENTS) {
			nent = PRIME_MAX_IDENTS;
		}
		p->empty[p->nempty].n = 0;
		for (j = 0; j < nent && p->empty[p->nempty].n < PRIME_MAX_IDENTS; j++) {
			char ident[PRIME_MAX_IDENTITY];
			unsigned long long work = 0, pub = 0;
			int nf;
			if (!fgets(line, sizeof line, f)) {
				break;
			}
			if (line[0] != ' ') {
				break;
			}
			nf = sscanf(line, " %127s %llu %llu", ident, &work, &pub);
			if (nf < 2) {
				break;
			}
			snprintf(p->empty[p->nempty].idents[p->empty[p->nempty].n],
				 PRIME_MAX_IDENTITY, "%s", ident);
			p->empty[p->nempty].work[p->empty[p->nempty].n] = work;
			p->empty[p->nempty].public_work[p->empty[p->nempty].n] = nf >= 3 ? pub : 0;
			p->empty[p->nempty].n++;
		}
		p->nempty++;
	}
	fclose(f);
}

static void print_empty_row(FILE *out, const prime_pool *p, size_t i)
{
	char hex[65];
	size_t j;
	prime_hex_encode(p->empty[i].hash, 32, hex, sizeof hex);
	fprintf(out, "empty height %u block %s found %llu value %llu work %llu fee %u bps %s",
		p->empty[i].height, hex, (unsigned long long)p->empty[i].at,
		(unsigned long long)p->empty[i].value,
		(unsigned long long)p->empty[i].total_work, (unsigned)p->empty[i].fee_bps,
		p->empty[i].settled_at ? "settled" : "unsettled");
	if (p->empty[i].settled_at) {
		fprintf(out, " at %llu", (unsigned long long)p->empty[i].settled_at);
	}
	if (p->empty[i].finder[0]) {
		fprintf(out, " finder %s", p->empty[i].finder);
	}
	fputc('\n', out);
	for (j = 0; j < p->empty[i].n; j++) {
		fprintf(out, "  %s %llu pub %llu\n", p->empty[i].idents[j],
			(unsigned long long)p->empty[i].work[j],
			(unsigned long long)p->empty[i].public_work[j]);
	}
}

static int empty_index(const prime_pool *p, const unsigned char hash[32])
{
	size_t i;
	for (i = 0; i < p->nempty; i++) {
		if (memcmp(p->empty[i].hash, hash, 32) == 0) {
			return (int)i;
		}
	}
	return -1;
}

static void load_blocks(prime_pool *p)
{
	FILE *f;
	char path[600], line[512];

	snprintf(path, sizeof path, "%s.blocks", p->path);
	f = fopen(path, "r");
	if (!f) {
		return;
	}
	while (fgets(line, sizeof line, f)) {
		char *s = line;
		while (*s == ' ' || *s == '\t') {
			s++;
		}
		if (*s == 0 || *s == '\n' || *s == '#') {
			continue;
		}
		p->blocks_found++;
	}
	fclose(f);
}

static void apply_fee_after_first(prime_pool *p)
{
	if (!p->fee_after_first_bps) {
		return;
	}
	p->fee_bps = p->blocks_found ? p->fee_after_first_bps : 0;
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
	p->window = 1;
	p->have_window = 0;
	p->min_payout = min_payout;
	p->fee_bps = fee_bps > 100 ? 100 : fee_bps;
	load_shares(p);
	if (load_window(p)) {
		trim(p);
	} else if (window) {
		p->window = window;
		p->have_window = 1;
		trim(p);
	}
	load_sessions(p);
	load_owed(p);
	load_empty(p);
	load_blocks(p);
	apply_fee_after_first(p);
	fprintf(stderr, "prime: ledger %s shares=%zu work=%llu window=%llu%s blocks=%llu owed=%zu empty=%zu\n",
		p->path, p->nshares, (unsigned long long)p->total_work,
		(unsigned long long)p->window, p->have_window ? "" : " (pending difficulty)",
		(unsigned long long)p->blocks_found, p->nowed, p->nempty);
	return p;
}

void prime_pool_set_fee_after_first_block(prime_pool *p, uint16_t after_bps)
{
	if (!p) {
		return;
	}
	pthread_mutex_lock(&p->mu);
	p->fee_after_first_bps = after_bps > 100 ? 100 : after_bps;
	apply_fee_after_first(p);
	pthread_mutex_unlock(&p->mu);
}

uint16_t prime_pool_fee_bps(const prime_pool *p)
{
	return p ? p->fee_bps : 0;
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
	p->have_window = 1;
	trim(p);
	save_window(p);
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
	ident_add(p, identity, difficulty, 1, share_tag_is_sv1(s.tag));
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

static uint64_t ident_side_work(const prime_ident_work *row, int public_side)
{
	if (public_side) {
		return row->public_work > row->work ? row->work : row->public_work;
	}
	return row->work > row->public_work ? row->work - row->public_work : 0;
}

static size_t pot_split(prime_ident_work *kept, size_t n, int public_side, uint64_t pot,
			uint64_t min_payout, char idents[][PRIME_MAX_IDENTITY], uint64_t *amounts,
			size_t max_n)
{
	size_t i, m = 0;
	uint64_t work = 0, left;
	prime_ident_work row[PRIME_MAX_IDENTS];

	if (!pot || !n || !max_n) {
		return 0;
	}
	for (i = 0; i < n; i++) {
		uint64_t w = ident_side_work(&kept[i], public_side);
		if (!w) {
			continue;
		}
		row[m] = kept[i];
		row[m].work = w;
		m++;
	}
	if (!m) {
		return 0;
	}
	qsort(row, m, sizeof row[0], cmp_ident_desc);
	if (m > max_n) {
		m = max_n;
	}
	for (i = 0; i < m; i++) {
		work += row[i].work;
	}
	while (m) {
		uint64_t w = row[m - 1].work;
		if (!work) {
			m = 0;
			break;
		}
		if ((uint64_t)((unsigned __int128)pot * w / work) >= min_payout) {
			break;
		}
		work -= w;
		m--;
	}
	left = pot;
	{
		size_t o = 0;
		for (i = 0; i < m; i++) {
			uint64_t amount;
			if (!work) {
				break;
			}
			amount = (uint64_t)((unsigned __int128)left * row[i].work / work);
			left -= amount;
			work -= row[i].work;
			if (!amount) {
				continue;
			}
			snprintf(idents[o], PRIME_MAX_IDENTITY, "%s", row[i].identity);
			amounts[o] = amount;
			o++;
		}
		return o;
	}
}

static size_t split_window(prime_ident_work *kept, size_t n, uint64_t total, uint64_t value,
			   uint16_t fee, uint64_t min_payout, char idents[][PRIME_MAX_IDENTITY],
			   uint64_t *amounts, size_t max_n)
{
	char dat_id[PRIME_MAX_SPLIT_OUTPUTS][PRIME_MAX_IDENTITY];
	char pub_id[PRIME_MAX_SPLIT_OUTPUTS][PRIME_MAX_IDENTITY];
	uint64_t dat_amt[PRIME_MAX_SPLIT_OUTPUTS];
	uint64_t pub_amt[PRIME_MAX_SPLIT_OUTPUTS];
	size_t i, nd = 0, np = 0, out = 0;
	uint64_t pub_w = 0, slice_pub, slice_dat, datum_fee, pub_fee, rebate;
	uint64_t datum_pot, pub_pot;

	if (!kept || !idents || !amounts || !n || !total || !max_n) {
		return 0;
	}
	for (i = 0; i < n; i++) {
		pub_w += ident_side_work(&kept[i], 1);
	}
	slice_pub = (uint64_t)((unsigned __int128)value * pub_w / total);
	if (slice_pub > value) {
		slice_pub = value;
	}
	slice_dat = value - slice_pub;
	datum_fee = (uint64_t)((unsigned __int128)slice_dat * fee / 10000);
	pub_fee = (uint64_t)((unsigned __int128)slice_pub * PRIME_SV1_FEE_BPS / 10000);
	rebate = (uint64_t)((unsigned __int128)slice_pub * PRIME_SV1_DATUM_REBATE_BPS / 10000);
	datum_pot = slice_dat - datum_fee + rebate;
	pub_pot = slice_pub - pub_fee;
	if (max_n > PRIME_MAX_SPLIT_OUTPUTS) {
		max_n = PRIME_MAX_SPLIT_OUTPUTS;
	}
	if (max_n > PRIME_MAX_COINBASER_OUTPUTS) {
		max_n = PRIME_MAX_COINBASER_OUTPUTS;
	}
	nd = pot_split(kept, n, 0, datum_pot, min_payout, dat_id, dat_amt, max_n);
	np = pot_split(kept, n, 1, pub_pot, min_payout, pub_id, pub_amt, max_n);
	for (i = 0; i < nd && out < max_n; i++) {
		snprintf(idents[out], PRIME_MAX_IDENTITY, "%s", dat_id[i]);
		amounts[out] = dat_amt[i];
		out++;
	}
	for (i = 0; i < np && out < max_n; i++) {
		size_t j, found = (size_t)-1;
		for (j = 0; j < out; j++) {
			if (strcmp(idents[j], pub_id[i]) == 0) {
				found = j;
				break;
			}
		}
		if (found != (size_t)-1) {
			amounts[found] += pub_amt[i];
			continue;
		}
		snprintf(idents[out], PRIME_MAX_IDENTITY, "%s", pub_id[i]);
		amounts[out] = pub_amt[i];
		out++;
	}
	return out;
}

size_t prime_pool_split(prime_pool *p, uint64_t value, char idents[][PRIME_MAX_IDENTITY],
			uint64_t *amounts, size_t max_n)
{
	prime_ident_work kept[PRIME_MAX_IDENTS];
	size_t n = 0;
	uint64_t min_payout, total;
	uint16_t fee;

	if (!p || !idents || !amounts || !max_n) {
		return 0;
	}
	pthread_mutex_lock(&p->mu);
	fee = p->fee_bps;
	min_payout = p->min_payout;
	total = p->total_work;
	if (!total) {
		pthread_mutex_unlock(&p->mu);
		return 0;
	}
	n = p->nidents;
	if (n > PRIME_MAX_IDENTS) {
		n = PRIME_MAX_IDENTS;
	}
	memcpy(kept, p->idents, n * sizeof kept[0]);
	pthread_mutex_unlock(&p->mu);
	return split_window(kept, n, total, value, fee, min_payout, idents, amounts, max_n);
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
	if (p->fee_after_first_bps && p->blocks_found == 1) {
		p->fee_bps = p->fee_after_first_bps;
		fprintf(stderr, "prime: first block found; fee now %u bps (%.2f%%)\n",
			(unsigned)p->fee_bps, (double)p->fee_bps / 100.0);
	}
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

static double work_to_hashrate_hs(uint64_t work)
{
	return prime_work_to_hashrate_hs(work, PRIME_HASHRATE_WINDOW_SEC);
}

double prime_work_to_hashrate_hs(uint64_t work, uint64_t seconds)
{
	if (!seconds) {
		seconds = 1;
	}
	return ((double)work * PRIME_HASHES_PER_DIFF) / (double)seconds;
}

static uint64_t ident_window_work(const prime_ident_work *snap, size_t n, const char *identity)
{
	size_t i;
	if (!identity) {
		return 0;
	}
	for (i = 0; i < n; i++) {
		if (strcmp(snap[i].identity, identity) == 0) {
			return snap[i].work;
		}
	}
	return 0;
}

int prime_pool_stats_json(prime_pool *p, char *out, size_t out_len)
{
	size_t i, n, si;
	int w;
	char *cur;
	size_t left;
	prime_ident_work snap[64];
	prime_ident_work rate[64];
	uint64_t total, shares, blocks, window, cutoff, pool_avg = 0;
	double pool_hs;
	if (!p || !out || out_len < 32) {
		return -1;
	}
	memset(rate, 0, sizeof rate);
	pthread_mutex_lock(&p->mu);
	total = p->total_work;
	shares = p->nshares;
	blocks = p->blocks_found;
	window = p->window;
	n = p->nidents < 64 ? p->nidents : 64;
	memcpy(snap, p->idents, n * sizeof snap[0]);
	memcpy(rate, snap, n * sizeof rate[0]);
	for (i = 0; i < n; i++) {
		rate[i].work = 0;
	}
	cutoff = (uint64_t)time(NULL);
	if (cutoff > PRIME_HASHRATE_WINDOW_SEC) {
		cutoff -= PRIME_HASHRATE_WINDOW_SEC;
	} else {
		cutoff = 0;
	}
	for (si = 0; si < p->nshares; si++) {
		const prime_share_row *s = &p->shares[(p->share_head + si) % PRIME_MAX_SHARES];
		if (s->at < cutoff) {
			continue;
		}
		pool_avg += s->difficulty;
		for (i = 0; i < n; i++) {
			if (strcmp(rate[i].identity, s->identity) == 0) {
				rate[i].work += s->difficulty;
				break;
			}
		}
	}
	pthread_mutex_unlock(&p->mu);
	qsort(snap, n, sizeof snap[0], cmp_ident_desc);
	pool_hs = work_to_hashrate_hs(pool_avg);
	cur = out;
	left = out_len;
	w = snprintf(cur, left,
		     "{\"shares\":%llu,\"work\":%llu,\"window\":%llu,\"blocks\":%llu,"
		     "\"hashrate_hs\":%.8g,\"hashrate_window_sec\":%u,\"miners\":[",
		     (unsigned long long)shares, (unsigned long long)total,
		     (unsigned long long)window, (unsigned long long)blocks, pool_hs,
		     (unsigned)PRIME_HASHRATE_WINDOW_SEC);
	if (w < 0 || (size_t)w >= left) {
		return -1;
	}
	cur += w;
	left -= (size_t)w;
	for (i = 0; i < n; i++) {
		double pct = total ? ((double)snap[i].work * 100.0 / (double)total) : 0.0;
		uint64_t avg = ident_window_work(rate, n, snap[i].identity);
		double hs = work_to_hashrate_hs(avg);
		double hpct = pool_avg ? ((double)avg * 100.0 / (double)pool_avg) : 0.0;
		w = snprintf(cur, left, "%s{\"id\":\"", i ? "," : "");
		if (w < 0 || (size_t)w >= left) {
			break;
		}
		cur += w;
		left -= (size_t)w;
		json_escape_append(&cur, &left, snap[i].identity);
		{
			uint64_t pub_w = snap[i].public_work > snap[i].work
					 ? snap[i].work : snap[i].public_work;
			uint64_t dat_w = snap[i].work > pub_w ? snap[i].work - pub_w : 0;
			const char *kind = pub_w == 0 ? "datum" : (dat_w == 0 ? "sv1" : "mixed");
			w = snprintf(cur, left,
				     "\",\"work\":%llu,\"datum_work\":%llu,\"public_work\":%llu,"
				     "\"kind\":\"%s\",\"window_percent\":%.6f,"
				     "\"hashrate_hs\":%.8g,\"hash_percent\":%.6f}",
				     (unsigned long long)snap[i].work,
				     (unsigned long long)dat_w, (unsigned long long)pub_w,
				     kind, pct, hs, hpct);
		}
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

double prime_pool_hashrate_hs(prime_pool *p)
{
	size_t si;
	uint64_t cutoff, work = 0;
	if (!p) {
		return 0;
	}
	pthread_mutex_lock(&p->mu);
	cutoff = (uint64_t)time(NULL);
	if (cutoff > PRIME_HASHRATE_WINDOW_SEC) {
		cutoff -= PRIME_HASHRATE_WINDOW_SEC;
	} else {
		cutoff = 0;
	}
	for (si = 0; si < p->nshares; si++) {
		const prime_share_row *s = &p->shares[(p->share_head + si) % PRIME_MAX_SHARES];
		if (s->at >= cutoff) {
			work += s->difficulty;
		}
	}
	pthread_mutex_unlock(&p->mu);
	return work_to_hashrate_hs(work);
}

int prime_pool_work_since(prime_pool *p, uint64_t cutoff, uint64_t *total,
			  uint64_t *sv1, uint64_t *oldest_at, uint64_t *count)
{
	size_t si;
	uint64_t tot = 0, pub = 0, n = 0, oldest = 0;
	if (!p) {
		return -1;
	}
	pthread_mutex_lock(&p->mu);
	for (si = 0; si < p->nshares; si++) {
		const prime_share_row *s = &p->shares[(p->share_head + si) % PRIME_MAX_SHARES];
		if (s->at < cutoff) {
			continue;
		}
		tot += s->difficulty;
		if (share_tag_is_sv1(s->tag)) {
			pub += s->difficulty;
		}
		if (!oldest || s->at < oldest) {
			oldest = s->at;
		}
		n++;
	}
	pthread_mutex_unlock(&p->mu);
	if (total) {
		*total = tot;
	}
	if (sv1) {
		*sv1 = pub;
	}
	if (oldest_at) {
		*oldest_at = oldest;
	}
	if (count) {
		*count = n;
	}
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

int prime_pool_shares_json(prime_pool *p, char *out, size_t out_len,
			   const unsigned char *after_hash, size_t limit)
{
	size_t i, n, emitted = 0, start = 0;
	int w;
	char *cur;
	size_t left;
	unsigned char last[32];
	int have_last = 0;

	if (!p || !out || out_len < 64) {
		return -1;
	}
	if (!limit) {
		limit = 500;
	}
	if (limit > 2000) {
		limit = 2000;
	}
	pthread_mutex_lock(&p->mu);
	n = p->nshares;
	if (after_hash) {
		int found = 0;
		for (i = 0; i < n; i++) {
			size_t idx = (p->share_head + i) % PRIME_MAX_SHARES;
			if (memcmp(p->shares[idx].hash, after_hash, 32) == 0) {
				start = i + 1;
				found = 1;
				break;
			}
		}
		if (!found) {
			start = n;
		}
	}
	cur = out;
	left = out_len;
	w = snprintf(cur, left,
		     "{\"schema_version\":1,\"updated_at\":%llu,\"shares\":%zu,\"work\":%llu,"
		     "\"window\":%llu,\"limit\":%zu,\"entries\":[",
		     (unsigned long long)time(NULL), n, (unsigned long long)p->total_work,
		     (unsigned long long)p->window, limit);
	if (w < 0 || (size_t)w >= left) {
		pthread_mutex_unlock(&p->mu);
		return -1;
	}
	cur += w;
	left -= (size_t)w;
	for (i = start; i < n && emitted < limit; i++) {
		char hex[65];
		size_t idx = (p->share_head + i) % PRIME_MAX_SHARES;
		const prime_share_row *s = &p->shares[idx];
		prime_hex_encode(s->hash, 32, hex, sizeof hex);
		w = snprintf(cur, left,
			     "%s{\"at\":%llu,\"difficulty\":%llu,\"id\":\"%s\",\"hash\":\"%s\"}",
			     emitted ? "," : "", (unsigned long long)s->at,
			     (unsigned long long)s->difficulty, s->identity, hex);
		if (w < 0 || (size_t)w >= left) {
			pthread_mutex_unlock(&p->mu);
			return -1;
		}
		cur += w;
		left -= (size_t)w;
		memcpy(last, s->hash, 32);
		have_last = 1;
		emitted++;
	}
	{
		int more = (start + emitted) < n;
		char next[65];
		next[0] = 0;
		if (more && have_last) {
			prime_hex_encode(last, 32, next, sizeof next);
		}
		w = snprintf(cur, left, "],\"count\":%zu,\"has_more\":%s,\"next_after\":\"%s\"}",
			     emitted, more ? "true" : "false", next);
	}
	pthread_mutex_unlock(&p->mu);
	if (w < 0 || (size_t)w >= left) {
		return -1;
	}
	return 0;
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

static void drop_empty_slot(prime_pool *p, size_t idx)
{
	if (idx + 1 < p->nempty) {
		memmove(&p->empty[idx], &p->empty[idx + 1],
			(p->nempty - idx - 1) * sizeof p->empty[0]);
	}
	p->nempty--;
}

static int evict_empty_for_add(prime_pool *p, int pending)
{
	size_t i;
	int drop = -1;
	if (p->nempty < PRIME_MAX_EMPTY) {
		return 0;
	}
	if (pending) {
		for (i = 0; i < p->nempty; i++) {
			if (!p->empty[i].pending && p->empty[i].settled_at) {
				drop = (int)i;
				break;
			}
		}
		if (drop < 0) {
			return -1;
		}
	} else {
		drop = 0;
	}
	drop_empty_slot(p, (size_t)drop);
	return 0;
}

static int add_empty_locked(prime_pool *p, uint32_t height, const unsigned char hash[32],
			    const char *finder, uint64_t value, int pending)
{
	size_t i, slot, n = 0;
	if (empty_index(p, hash) >= 0) {
		return 0;
	}
	if (evict_empty_for_add(p, pending) != 0) {
		return -1;
	}
	slot = p->nempty++;
	memset(&p->empty[slot], 0, sizeof p->empty[slot]);
	p->empty[slot].at = (uint64_t)time(NULL);
	p->empty[slot].height = height;
	memcpy(p->empty[slot].hash, hash, 32);
	p->empty[slot].value = value;
	p->empty[slot].total_work = p->total_work;
	p->empty[slot].fee_bps = p->fee_bps;
	p->empty[slot].min_payout = p->min_payout;
	p->empty[slot].pending = pending ? 1 : 0;
	snprintf(p->empty[slot].finder, sizeof p->empty[slot].finder, "%s", finder ? finder : "");
	for (i = 0; i < p->nidents && n < PRIME_MAX_IDENTS; i++) {
		if (!p->idents[i].work) {
			continue;
		}
		snprintf(p->empty[slot].idents[n], PRIME_MAX_IDENTITY, "%s", p->idents[i].identity);
		p->empty[slot].work[n] = p->idents[i].work;
		p->empty[slot].public_work[n] = p->idents[i].public_work;
		n++;
	}
	p->empty[slot].n = n;
	if (!pending) {
		save_empty(p);
	}
	return 0;
}

int prime_pool_record_empty(prime_pool *p, uint32_t height, const unsigned char hash[32],
			    const char *finder, uint64_t value)
{
	int idx;
	size_t n = 0;
	if (!p || !hash) {
		return -1;
	}
	pthread_mutex_lock(&p->mu);
	add_empty_locked(p, height, hash, finder, value, 0);
	idx = empty_index(p, hash);
	if (idx >= 0) {
		n = p->empty[idx].n;
	}
	pthread_mutex_unlock(&p->mu);
	fprintf(stderr, "prime: empty find height %u snapshot %zu identities value %llu\n",
		(unsigned)height, n, (unsigned long long)value);
	return 0;
}

int prime_pool_prepare_empty(prime_pool *p, uint32_t height, const unsigned char hash[32],
			     const char *finder, uint64_t value)
{
	if (!p || !hash) {
		return -1;
	}
	pthread_mutex_lock(&p->mu);
	if (add_empty_locked(p, height, hash, finder, value, 1) != 0) {
		pthread_mutex_unlock(&p->mu);
		return -1;
	}
	pthread_mutex_unlock(&p->mu);
	return 0;
}

int prime_pool_commit_empty(prime_pool *p, const unsigned char hash[32])
{
	int idx;
	size_t n = 0;
	uint32_t height = 0;
	uint64_t value = 0;
	if (!p || !hash) {
		return -1;
	}
	pthread_mutex_lock(&p->mu);
	idx = empty_index(p, hash);
	if (idx < 0) {
		pthread_mutex_unlock(&p->mu);
		return 1;
	}
	if (p->empty[idx].pending) {
		p->empty[idx].pending = 0;
		save_empty(p);
	}
	height = p->empty[idx].height;
	n = p->empty[idx].n;
	value = p->empty[idx].value;
	pthread_mutex_unlock(&p->mu);
	fprintf(stderr, "prime: empty find height %u snapshot %zu identities value %llu\n",
		(unsigned)height, n, (unsigned long long)value);
	return 0;
}

int prime_pool_abort_empty(prime_pool *p, const unsigned char hash[32])
{
	int idx;
	if (!p || !hash) {
		return -1;
	}
	pthread_mutex_lock(&p->mu);
	idx = empty_index(p, hash);
	if (idx < 0 || !p->empty[idx].pending) {
		pthread_mutex_unlock(&p->mu);
		return 1;
	}
	if ((size_t)idx + 1 < p->nempty) {
		memmove(&p->empty[idx], &p->empty[idx + 1],
			(p->nempty - (size_t)idx - 1) * sizeof p->empty[0]);
	}
	p->nempty--;
	pthread_mutex_unlock(&p->mu);
	return 0;
}

int prime_pool_list_empty(prime_pool *p, FILE *out)
{
	size_t i;
	int any = 0;
	if (!p || !out) {
		return -1;
	}
	pthread_mutex_lock(&p->mu);
	for (i = 0; i < p->nempty; i++) {
		if (!p->empty[i].pending) {
			print_empty_row(out, p, i);
			any = 1;
		}
	}
	if (!any) {
		fprintf(out, "no empty finds\n");
	}
	pthread_mutex_unlock(&p->mu);
	return 0;
}

static int ident_json_safe(const char *s)
{
	if (!s || !s[0]) {
		return 0;
	}
	for (; *s; s++) {
		unsigned char c = (unsigned char)*s;
		if (c < 32 || c == '"' || c == '\\') {
			return 0;
		}
	}
	return 1;
}

int prime_pool_empty_sendmany(prime_pool *p, const unsigned char hash[32], FILE *out)
{
	int idx;
	size_t i, n, nout;
	uint64_t leftover;
	int first = 1;
	prime_ident_work kept[PRIME_MAX_IDENTS];
	char pay_id[PRIME_MAX_SPLIT_OUTPUTS][PRIME_MAX_IDENTITY];
	uint64_t pay_amt[PRIME_MAX_SPLIT_OUTPUTS];

	if (!p || !hash || !out) {
		return -1;
	}
	pthread_mutex_lock(&p->mu);
	idx = empty_index(p, hash);
	if (idx < 0 || p->empty[idx].pending) {
		pthread_mutex_unlock(&p->mu);
		return 1;
	}
	print_empty_row(out, p, (size_t)idx);
	leftover = p->empty[idx].value;
	n = p->empty[idx].n;
	if (n > PRIME_MAX_IDENTS) {
		n = PRIME_MAX_IDENTS;
	}
	memset(kept, 0, n * sizeof kept[0]);
	for (i = 0; i < n; i++) {
		snprintf(kept[i].identity, PRIME_MAX_IDENTITY, "%s", p->empty[idx].idents[i]);
		kept[i].work = p->empty[idx].work[i];
		kept[i].public_work = p->empty[idx].public_work[i];
	}
	fprintf(out, "# mature after height %u (coinbase 100 blocks)\n",
		p->empty[idx].height + 100);
	fprintf(out, "# same split as a live coinbase (fee %u bps, sv1 %u bps, cap %u)\n",
		(unsigned)p->empty[idx].fee_bps, (unsigned)PRIME_SV1_FEE_BPS,
		(unsigned)PRIME_MAX_SPLIT_OUTPUTS);
	if (!p->empty[idx].total_work || !p->empty[idx].value) {
		fprintf(out, "# no window work; keep the coinbase on the pool script\n");
		pthread_mutex_unlock(&p->mu);
		return 0;
	}
	nout = split_window(kept, n, p->empty[idx].total_work, p->empty[idx].value,
			    p->empty[idx].fee_bps, p->empty[idx].min_payout, pay_id, pay_amt,
			    PRIME_MAX_SPLIT_OUTPUTS);
	for (i = 0; i < nout; i++) {
		uint64_t amt = pay_amt[i];
		if (!amt || !ident_json_safe(pay_id[i])) {
			continue;
		}
		if (amt > leftover) {
			amt = leftover;
		}
		leftover -= amt;
		if (first) {
			fprintf(out, "bitcoin-cli sendmany \"\" '{");
		}
		fprintf(out, "%s\"%s\":%llu.%08llu", first ? "" : ",", pay_id[i],
			(unsigned long long)(amt / 100000000ull),
			(unsigned long long)(amt % 100000000ull));
		first = 0;
	}
	if (first) {
		fprintf(out, "# no outputs above min payout; keep the coinbase on the pool script\n");
	} else {
		fprintf(out, "}'\n");
	}
	fprintf(out, "# leftover %llu sats stay on the pool script (fee, dust, or 128 cap)\n",
		(unsigned long long)leftover);
	pthread_mutex_unlock(&p->mu);
	return 0;
}

int prime_pool_settle_empty(prime_pool *p, const unsigned char hash[32], uint64_t at)
{
	int idx;
	if (!p || !hash) {
		return -1;
	}
	pthread_mutex_lock(&p->mu);
	idx = empty_index(p, hash);
	if (idx < 0 || p->empty[idx].pending) {
		pthread_mutex_unlock(&p->mu);
		return 1;
	}
	if (!p->empty[idx].settled_at) {
		p->empty[idx].settled_at = at ? at : 1;
		save_empty(p);
	}
	print_empty_row(stdout, p, (size_t)idx);
	pthread_mutex_unlock(&p->mu);
	return 0;
}

int prime_pool_void_empty(prime_pool *p, const unsigned char hash[32])
{
	int idx;
	if (!p || !hash) {
		return -1;
	}
	pthread_mutex_lock(&p->mu);
	idx = empty_index(p, hash);
	if (idx < 0) {
		pthread_mutex_unlock(&p->mu);
		return 1;
	}
	print_empty_row(stdout, p, (size_t)idx);
	if ((size_t)idx + 1 < p->nempty) {
		memmove(&p->empty[idx], &p->empty[idx + 1],
			(p->nempty - (size_t)idx - 1) * sizeof p->empty[0]);
	}
	p->nempty--;
	save_empty(p);
	pthread_mutex_unlock(&p->mu);
	return 0;
}

size_t prime_pool_empty_count(prime_pool *p)
{
	size_t i, n;
	if (!p) {
		return 0;
	}
	pthread_mutex_lock(&p->mu);
	n = 0;
	for (i = 0; i < p->nempty; i++) {
		if (!p->empty[i].pending) {
			n++;
		}
	}
	pthread_mutex_unlock(&p->mu);
	return n;
}

size_t prime_pool_empty_unsettled(prime_pool *p)
{
	size_t i, n = 0;
	if (!p) {
		return 0;
	}
	pthread_mutex_lock(&p->mu);
	for (i = 0; i < p->nempty; i++) {
		if (!p->empty[i].pending && !p->empty[i].settled_at) {
			n++;
		}
	}
	pthread_mutex_unlock(&p->mu);
	return n;
}

int prime_pool_empty_json(prime_pool *p, char *out, size_t out_len)
{
	size_t i, finds = 0, unsettled = 0;
	int w;
	char *cur;
	size_t left;

	if (!p || !out || out_len < 64) {
		return -1;
	}
	pthread_mutex_lock(&p->mu);
	for (i = 0; i < p->nempty; i++) {
		if (p->empty[i].pending) {
			continue;
		}
		finds++;
		if (!p->empty[i].settled_at) {
			unsettled++;
		}
	}
	cur = out;
	left = out_len;
	w = snprintf(cur, left,
		     "{\"schema_version\":1,\"updated_at\":%llu,\"empty_finds\":%zu,"
		     "\"empty_unsettled\":%zu,\"finds\":[",
		     (unsigned long long)time(NULL), finds, unsettled);
	if (w < 0 || (size_t)w >= left) {
		pthread_mutex_unlock(&p->mu);
		return -1;
	}
	cur += w;
	left -= (size_t)w;
	finds = 0;
	for (i = 0; i < p->nempty; i++) {
		char hex[65], block[65];
		unsigned char rev[32];
		prime_ident_work kept[PRIME_MAX_IDENTS];
		char pay_id[PRIME_MAX_SPLIT_OUTPUTS][PRIME_MAX_IDENTITY];
		uint64_t pay_amt[PRIME_MAX_SPLIT_OUTPUTS];
		size_t j, n, nout, k;
		uint64_t leftover;
		int first_m = 1, first_p = 1;

		if (p->empty[i].pending) {
			continue;
		}
		for (k = 0; k < 32; k++) {
			rev[k] = p->empty[i].hash[31 - k];
		}
		prime_hex_encode(p->empty[i].hash, 32, hex, sizeof hex);
		prime_hex_encode(rev, 32, block, sizeof block);
		w = snprintf(cur, left,
			     "%s{\"height\":%u,\"hash\":\"%s\",\"block\":\"%s\",\"found_at\":%llu,"
			     "\"value\":%llu,\"work\":%llu,\"fee_bps\":%u,\"min_payout_sats\":%llu,"
			     "\"mature_after_height\":%u,\"settled\":%s,\"settled_at\":%llu,"
			     "\"finder\":\"",
			     finds ? "," : "", p->empty[i].height, hex, block,
			     (unsigned long long)p->empty[i].at,
			     (unsigned long long)p->empty[i].value,
			     (unsigned long long)p->empty[i].total_work,
			     (unsigned)p->empty[i].fee_bps,
			     (unsigned long long)p->empty[i].min_payout,
			     p->empty[i].height + 100,
			     p->empty[i].settled_at ? "true" : "false",
			     (unsigned long long)p->empty[i].settled_at);
		if (w < 0 || (size_t)w >= left) {
			pthread_mutex_unlock(&p->mu);
			return -1;
		}
		cur += w;
		left -= (size_t)w;
		json_escape_append(&cur, &left, p->empty[i].finder);
		w = snprintf(cur, left, "\",\"miners\":[");
		if (w < 0 || (size_t)w >= left) {
			pthread_mutex_unlock(&p->mu);
			return -1;
		}
		cur += w;
		left -= (size_t)w;
		n = p->empty[i].n;
		if (n > PRIME_MAX_IDENTS) {
			n = PRIME_MAX_IDENTS;
		}
		memset(kept, 0, n * sizeof kept[0]);
		for (j = 0; j < n; j++) {
			uint64_t pub_w = p->empty[i].public_work[j] > p->empty[i].work[j]
						 ? p->empty[i].work[j]
						 : p->empty[i].public_work[j];
			uint64_t dat_w = p->empty[i].work[j] > pub_w ? p->empty[i].work[j] - pub_w
								     : 0;
			const char *kind = pub_w == 0 ? "datum" : (dat_w == 0 ? "sv1" : "mixed");
			double pct = p->empty[i].total_work
					     ? ((double)p->empty[i].work[j] * 100.0
						/ (double)p->empty[i].total_work)
					     : 0.0;
			w = snprintf(cur, left, "%s{\"id\":\"", first_m ? "" : ",");
			if (w < 0 || (size_t)w >= left) {
				pthread_mutex_unlock(&p->mu);
				return -1;
			}
			cur += w;
			left -= (size_t)w;
			json_escape_append(&cur, &left, p->empty[i].idents[j]);
			w = snprintf(cur, left,
				     "\",\"work\":%llu,\"datum_work\":%llu,\"public_work\":%llu,"
				     "\"kind\":\"%s\",\"window_percent\":%.6f}",
				     (unsigned long long)p->empty[i].work[j],
				     (unsigned long long)dat_w, (unsigned long long)pub_w, kind,
				     pct);
			if (w < 0 || (size_t)w >= left) {
				pthread_mutex_unlock(&p->mu);
				return -1;
			}
			cur += w;
			left -= (size_t)w;
			first_m = 0;
			snprintf(kept[j].identity, PRIME_MAX_IDENTITY, "%s", p->empty[i].idents[j]);
			kept[j].work = p->empty[i].work[j];
			kept[j].public_work = p->empty[i].public_work[j];
		}
		leftover = p->empty[i].value;
		nout = 0;
		if (p->empty[i].total_work && p->empty[i].value) {
			nout = split_window(kept, n, p->empty[i].total_work, p->empty[i].value,
					    p->empty[i].fee_bps, p->empty[i].min_payout, pay_id,
					    pay_amt, PRIME_MAX_SPLIT_OUTPUTS);
		}
		w = snprintf(cur, left, "],\"payouts\":[");
		if (w < 0 || (size_t)w >= left) {
			pthread_mutex_unlock(&p->mu);
			return -1;
		}
		cur += w;
		left -= (size_t)w;
		for (j = 0; j < nout; j++) {
			if (!pay_amt[j]) {
				continue;
			}
			if (pay_amt[j] > leftover) {
				pay_amt[j] = leftover;
			}
			leftover -= pay_amt[j];
			w = snprintf(cur, left, "%s{\"id\":\"", first_p ? "" : ",");
			if (w < 0 || (size_t)w >= left) {
				pthread_mutex_unlock(&p->mu);
				return -1;
			}
			cur += w;
			left -= (size_t)w;
			json_escape_append(&cur, &left, pay_id[j]);
			w = snprintf(cur, left, "\",\"sats\":%llu}", (unsigned long long)pay_amt[j]);
			if (w < 0 || (size_t)w >= left) {
				pthread_mutex_unlock(&p->mu);
				return -1;
			}
			cur += w;
			left -= (size_t)w;
			first_p = 0;
		}
		w = snprintf(cur, left, "],\"leftover_sats\":%llu}", (unsigned long long)leftover);
		if (w < 0 || (size_t)w >= left) {
			pthread_mutex_unlock(&p->mu);
			return -1;
		}
		cur += w;
		left -= (size_t)w;
		finds++;
	}
	if (left < 3) {
		pthread_mutex_unlock(&p->mu);
		return -1;
	}
	memcpy(cur, "]}", 3);
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
	fprintf(out, "shares %zu work %llu window %llu blocks %llu owed %zu empty %zu\n",
		p->nshares, (unsigned long long)p->total_work, (unsigned long long)p->window,
		(unsigned long long)p->blocks_found, p->nowed, p->nempty);
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
	for (i = 0; i < p->nempty; i++) {
		if (!p->empty[i].pending) {
			print_empty_row(out, p, i);
		}
	}
	pthread_mutex_unlock(&p->mu);
	return 0;
}
