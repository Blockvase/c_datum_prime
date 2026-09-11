/* Translated from RATUM prime/src/abw.rs and core/src/datum/abw.rs by iohzrd.
 * Copyright (C) iohzrd and RATUM contributors
 * Copyright (C) Blockvase contributors (C translation)
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#include "prime.h"

#include <stdlib.h>
#include <string.h>

void prime_xor_key_hash(const unsigned char xor_key[16], unsigned char out[32])
{
	prime_tagged_sha256("Bitcoin block hash PoW XOR key", xor_key, 16, out);
}

uint8_t prime_abw_clear_bits(uint8_t pot)
{
	unsigned n = 32u + (unsigned)pot;
	return n > 255u ? 255 : (uint8_t)n;
}

void prime_xor_mask(const unsigned char xor_key[16], uint8_t clear_bits, unsigned char out[32])
{
	unsigned i, clear_bytes;
	int z = 1;
	for (i = 0; i < 16; i++) {
		if (xor_key[i]) {
			z = 0;
			break;
		}
	}
	if (z) {
		memset(out, 0, 32);
		return;
	}
	prime_tagged_sha256("Bitcoin block hash PoW XOR mask", xor_key, 16, out);
	clear_bytes = clear_bits / 8;
	for (i = 0; i < clear_bytes && i < 32; i++) {
		out[i] = 0;
	}
	if (clear_bytes < 32) {
		out[clear_bytes] &= (unsigned char)(0xffu >> (clear_bits % 8));
	}
}

static void seed_slot(prime_abw *a, uint8_t slot)
{
	randombytes_buf(a->keys[slot], 16);
	a->have_key[slot] = 1;
	a->have_revealed[slot] = 0;
	memset(a->revealed[slot], 0, 16);
	a->active = slot;
	a->shares = 0;
	a->activated_at = time(NULL);
	a->retired_at[slot] = 0;
	a->retired_sent[slot] = 0;
}

void prime_abw_start(prime_abw *a, unsigned reveal_after_sec)
{
	memset(a, 0, sizeof *a);
	a->reveal_after_sec = reveal_after_sec ? reveal_after_sec : 300;
	seed_slot(a, 0);
}

void prime_abw_resumed(prime_abw *a)
{
	int i;
	time_t now = time(NULL);
	a->activated_at = now;
	for (i = 0; i < PRIME_ABW_SLOTS; i++) {
		if (a->have_key[i] && i != a->active) {
			a->retired_at[i] = now;
		}
		if (a->have_revealed[i] && !a->have_key[i]) {
			a->retired_at[i] = now;
			a->retired_sent[i] = 1;
		}
	}
}

int prime_abw_key(const prime_abw *a, uint8_t slot, unsigned char key[16])
{
	if (slot >= PRIME_ABW_SLOTS) {
		return -1;
	}
	if (a->have_key[slot]) {
		memcpy(key, a->keys[slot], 16);
		return 0;
	}
	if (a->have_revealed[slot]) {
		memcpy(key, a->revealed[slot], 16);
		return 0;
	}
	return -1;
}

int prime_abw_encode_notice(const prime_abw *a, uint8_t slot, int active,
			    unsigned char **out, size_t *out_len)
{
	unsigned char kh[32];
	unsigned char *p;
	if (slot >= PRIME_ABW_SLOTS || !a->have_key[slot]) {
		return -1;
	}
	p = malloc(37);
	if (!p) {
		return -1;
	}
	prime_xor_key_hash(a->keys[slot], kh);
	p[0] = PRIME_ABW_NOTICE;
	p[1] = 0;
	p[2] = active ? 1 : 0;
	p[3] = slot;
	memcpy(p + 4, kh, 32);
	p[36] = PRIME_STRUCT_END;
	*out = p;
	*out_len = 37;
	return 0;
}

int prime_abw_encode_notices(const prime_abw *a, unsigned char ***out, size_t **lens, size_t *n)
{
	unsigned char **msgs = NULL;
	size_t *ls = NULL;
	size_t count = 0, i;
	int slot;

	*out = NULL;
	*lens = NULL;
	*n = 0;
	for (slot = 0; slot < PRIME_ABW_SLOTS; slot++) {
		if (a->have_key[slot] && slot != a->active && !a->retired_sent[slot]) {
			count++;
		}
	}
	if (a->have_key[a->active]) {
		count++;
	}
	if (!count) {
		return 0;
	}
	msgs = calloc(count, sizeof *msgs);
	ls = calloc(count, sizeof *ls);
	if (!msgs || !ls) {
		free(msgs);
		free(ls);
		return -1;
	}
	i = 0;
	for (slot = 0; slot < PRIME_ABW_SLOTS; slot++) {
		if (a->have_key[slot] && slot != a->active && !a->retired_sent[slot]) {
			if (prime_abw_encode_notice(a, (uint8_t)slot, 0, &msgs[i], &ls[i]) != 0) {
				continue;
			}
			i++;
		}
	}
	if (a->have_key[a->active]) {
		if (prime_abw_encode_notice(a, a->active, 1, &msgs[i], &ls[i]) == 0) {
			i++;
		}
	}
	*out = msgs;
	*lens = ls;
	*n = i;
	return 0;
}

int prime_abw_encode_receipt(uint8_t slot, const unsigned char raw_le[32],
			     unsigned char **out, size_t *out_len)
{
	unsigned char *p = malloc(36);
	if (!p) {
		return -1;
	}
	p[0] = PRIME_ABW_RECEIPT;
	p[1] = 0;
	p[2] = slot;
	memcpy(p + 3, raw_le, 32);
	p[35] = PRIME_STRUCT_END;
	*out = p;
	*out_len = 36;
	return 0;
}

int prime_abw_encode_reveal(uint8_t slot, const unsigned char key[16],
			    unsigned char **out, size_t *out_len)
{
	unsigned char *p = malloc(20);
	if (!p) {
		return -1;
	}
	p[0] = PRIME_ABW_REVEAL;
	p[1] = 0;
	p[2] = slot;
	memcpy(p + 3, key, 16);
	p[19] = PRIME_STRUCT_END;
	*out = p;
	*out_len = 20;
	return 0;
}

static int reveal_slot(prime_abw *a, uint8_t slot, unsigned char **out, size_t *out_len)
{
	unsigned char key[16];
	if (a->retired_sent[slot] && a->have_revealed[slot]) {
		memcpy(key, a->revealed[slot], 16);
	} else if (a->have_key[slot]) {
		memcpy(key, a->keys[slot], 16);
		memcpy(a->revealed[slot], key, 16);
		a->have_revealed[slot] = 1;
		a->have_key[slot] = 0;
		memset(a->keys[slot], 0, 16);
	} else {
		return -1;
	}
	a->retired_at[slot] = 0;
	a->retired_sent[slot] = 0;
	return prime_abw_encode_reveal(slot, key, out, out_len);
}

int prime_abw_on_share(prime_abw *a, unsigned char **rotate_wire, size_t *rotate_len)
{
	time_t now = time(NULL);
	uint8_t old, next;
	unsigned char *rev = NULL, *notice = NULL;
	size_t rev_len = 0, notice_len = 0;

	*rotate_wire = NULL;
	*rotate_len = 0;
	a->shares++;
	if (a->shares < PRIME_ABW_ROTATE_SHARES && now - a->activated_at < 600) {
		return 0;
	}
	old = a->active;
	next = (uint8_t)((old + 1) % PRIME_ABW_SLOTS);
	if (a->have_key[next] || (a->have_revealed[next] && a->retired_at[next])) {
		reveal_slot(a, next, &rev, &rev_len);
	}
	a->retired_at[old] = now;
	a->retired_sent[old] = 0;
	seed_slot(a, next);
	if (prime_abw_encode_notice(a, next, 1, &notice, &notice_len) != 0) {
		free(rev);
		return -1;
	}
	{
		size_t n = rev_len + notice_len;
		unsigned char *both = malloc(n);
		if (!both) {
			free(rev);
			free(notice);
			return -1;
		}
		if (rev && rev_len) {
			memcpy(both, rev, rev_len);
			memcpy(both + rev_len, notice, notice_len);
		} else {
			memcpy(both, notice, notice_len);
		}
		free(rev);
		free(notice);
		*rotate_wire = both;
		*rotate_len = n;
	}
	return 0;
}

int prime_abw_due_reveals(prime_abw *a, unsigned char ***out, size_t **lens, size_t *n)
{
	unsigned char *tmp[PRIME_ABW_SLOTS];
	size_t ls[PRIME_ABW_SLOTS];
	size_t count = 0;
	int slot;
	time_t now = time(NULL);

	*out = NULL;
	*lens = NULL;
	*n = 0;
	for (slot = 0; slot < PRIME_ABW_SLOTS; slot++) {
		if (slot == a->active) {
			continue;
		}
		if (!a->retired_at[slot]) {
			continue;
		}
		if ((unsigned)(now - a->retired_at[slot]) < a->reveal_after_sec) {
			continue;
		}
		if (reveal_slot(a, (uint8_t)slot, &tmp[count], &ls[count]) == 0) {
			count++;
		}
	}
	if (!count) {
		return 0;
	}
	*out = malloc(count * sizeof **out);
	*lens = malloc(count * sizeof **lens);
	if (!*out || !*lens) {
		size_t i;
		for (i = 0; i < count; i++) {
			free(tmp[i]);
		}
		free(*out);
		free(*lens);
		*out = NULL;
		*lens = NULL;
		return -1;
	}
	memcpy(*out, tmp, count * sizeof *tmp);
	memcpy(*lens, ls, count * sizeof *ls);
	*n = count;
	return 0;
}
