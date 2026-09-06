/* Translated from RATUM core/src/datum/framing.rs by iohzrd.
 * Copyright (C) iohzrd and RATUM contributors
 * Copyright (C) Blockvase contributors (C translation)
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#include "prime.h"

#include <string.h>

uint32_t prime_feedback(uint32_t i)
{
	uint32_t h = 0xb10cfeedu;
	uint32_t k = i;
	k *= 0xcc9e2d51u;
	k = (k << 15) | (k >> 17);
	k *= 0x1b873593u;
	h ^= k;
	h = (h << 13) | (h >> 19);
	h = h * 5u + 0xe6546b64u;
	h ^= 4u;
	h ^= h >> 16;
	h *= 0x85ebca6bu;
	h ^= h >> 13;
	h *= 0xc2b2ae35u;
	h ^= h >> 16;
	return h;
}

void prime_header_to_bytes(const prime_header *h, unsigned char out[4])
{
	uint32_t v = (h->cmd_len & PRIME_MAX_CMD_LEN)
		| ((uint32_t)(h->reserved & 0x3) << 22)
		| ((uint32_t)(h->is_signed ? 1 : 0) << 24)
		| ((uint32_t)(h->is_encrypted_pubkey ? 1 : 0) << 25)
		| ((uint32_t)(h->is_encrypted_channel ? 1 : 0) << 26)
		| ((uint32_t)(h->proto_cmd & 0x1f) << 27);
	out[0] = (unsigned char)(v);
	out[1] = (unsigned char)(v >> 8);
	out[2] = (unsigned char)(v >> 16);
	out[3] = (unsigned char)(v >> 24);
}

int prime_header_from_bytes(const unsigned char in[4], prime_header *h)
{
	uint32_t v = (uint32_t)in[0] | ((uint32_t)in[1] << 8)
		| ((uint32_t)in[2] << 16) | ((uint32_t)in[3] << 24);
	h->cmd_len = v & PRIME_MAX_CMD_LEN;
	h->reserved = (uint8_t)((v >> 22) & 0x3);
	h->is_signed = (v & (1u << 24)) != 0;
	h->is_encrypted_pubkey = (v & (1u << 25)) != 0;
	h->is_encrypted_channel = (v & (1u << 26)) != 0;
	h->proto_cmd = (uint8_t)((v >> 27) & 0x1f);
	return 0;
}

void prime_ratchet_init(prime_ratchet *r, uint32_t key)
{
	r->key = key;
}

void prime_ratchet_hello(prime_ratchet *r)
{
	r->key = PRIME_INITIAL_HELLO_KEY;
}

void prime_ratchet_mask(prime_ratchet *r, const prime_header *h, unsigned char out[4])
{
	unsigned char raw[4];
	uint32_t v;
	prime_header_to_bytes(h, raw);
	v = (uint32_t)raw[0] | ((uint32_t)raw[1] << 8)
		| ((uint32_t)raw[2] << 16) | ((uint32_t)raw[3] << 24);
	v ^= r->key;
	out[0] = (unsigned char)(v);
	out[1] = (unsigned char)(v >> 8);
	out[2] = (unsigned char)(v >> 16);
	out[3] = (unsigned char)(v >> 24);
	r->key = prime_feedback(r->key);
}

void prime_ratchet_unmask(prime_ratchet *r, const unsigned char in[4], prime_header *h)
{
	uint32_t v = (uint32_t)in[0] | ((uint32_t)in[1] << 8)
		| ((uint32_t)in[2] << 16) | ((uint32_t)in[3] << 24);
	unsigned char raw[4];
	v ^= r->key;
	raw[0] = (unsigned char)(v);
	raw[1] = (unsigned char)(v >> 8);
	raw[2] = (unsigned char)(v >> 16);
	raw[3] = (unsigned char)(v >> 24);
	prime_header_from_bytes(raw, h);
	r->key = prime_feedback(r->key);
}

void prime_header_keys_from_nk(uint32_t nk, uint32_t *client_to_server, uint32_t *server_to_client)
{
	*client_to_server = prime_feedback(nk);
	*server_to_client = prime_feedback(~nk);
}

void prime_derive_nonces(uint32_t nk, const unsigned char session_pk_ed25519[32],
			 unsigned char client_receiver[PRIME_NONCE_LEN],
			 unsigned char client_sender[PRIME_NONCE_LEN])
{
	uint32_t n = nk - 42u;
	int j;
	n ^= (uint32_t)session_pk_ed25519[7]
		| ((uint32_t)session_pk_ed25519[8] << 8)
		| ((uint32_t)session_pk_ed25519[9] << 16)
		| ((uint32_t)session_pk_ed25519[10] << 24);
	for (j = 0; j < PRIME_NONCE_LEN; j += 4) {
		uint32_t r = prime_feedback(n - 42u);
		uint32_t s = r ^ 0x57575757u;
		client_receiver[j] = (unsigned char)(r);
		client_receiver[j + 1] = (unsigned char)(r >> 8);
		client_receiver[j + 2] = (unsigned char)(r >> 16);
		client_receiver[j + 3] = (unsigned char)(r >> 24);
		client_sender[j] = (unsigned char)(s);
		client_sender[j + 1] = (unsigned char)(s >> 8);
		client_sender[j + 2] = (unsigned char)(s >> 16);
		client_sender[j + 3] = (unsigned char)(s >> 24);
		n = ~r;
	}
}

void prime_increment_nonce(unsigned char nonce[PRIME_NONCE_LEN])
{
	int j;
	for (j = 0; j < PRIME_NONCE_LEN; j += 4) {
		uint32_t w = (uint32_t)nonce[j] | ((uint32_t)nonce[j + 1] << 8)
			| ((uint32_t)nonce[j + 2] << 16) | ((uint32_t)nonce[j + 3] << 24);
		w += 1u;
		nonce[j] = (unsigned char)(w);
		nonce[j + 1] = (unsigned char)(w >> 8);
		nonce[j + 2] = (unsigned char)(w >> 16);
		nonce[j + 3] = (unsigned char)(w >> 24);
		if (w != 0) {
			return;
		}
	}
}

static int hex_nibble(char c)
{
	if (c >= '0' && c <= '9') {
		return c - '0';
	}
	if (c >= 'a' && c <= 'f') {
		return c - 'a' + 10;
	}
	if (c >= 'A' && c <= 'F') {
		return c - 'A' + 10;
	}
	return -1;
}

int prime_hex_encode(const unsigned char *bin, size_t bin_len, char *out, size_t out_len)
{
	static const char hex[] = "0123456789abcdef";
	size_t i;
	if (out_len < bin_len * 2 + 1) {
		return -1;
	}
	for (i = 0; i < bin_len; i++) {
		out[i * 2] = hex[bin[i] >> 4];
		out[i * 2 + 1] = hex[bin[i] & 0xf];
	}
	out[bin_len * 2] = 0;
	return 0;
}

int prime_hex_decode(const char *hex, unsigned char *out, size_t out_len)
{
	size_t i;
	size_t n = strlen(hex);
	if (n != out_len * 2) {
		return -1;
	}
	for (i = 0; i < out_len; i++) {
		int hi = hex_nibble(hex[i * 2]);
		int lo = hex_nibble(hex[i * 2 + 1]);
		if (hi < 0 || lo < 0) {
			return -1;
		}
		out[i] = (unsigned char)((hi << 4) | lo);
	}
	return 0;
}
