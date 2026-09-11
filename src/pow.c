/* Translated from RATUM core/src/header.rs and core/src/target.rs by iohzrd.
 * Copyright (C) iohzrd and RATUM contributors
 * Copyright (C) Blockvase contributors (C translation)
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#include "prime.h"

#include <stdlib.h>
#include <string.h>

void prime_sha256(const unsigned char *in, size_t in_len, unsigned char out[32])
{
	crypto_hash_sha256(out, in, in_len);
}

void prime_sha256d(const unsigned char *in, size_t in_len, unsigned char out[32])
{
	unsigned char mid[32];
	prime_sha256(in, in_len, mid);
	prime_sha256(mid, 32, out);
}

void prime_tagged_sha256(const char *tag, const unsigned char *data, size_t data_len,
			 unsigned char out[32])
{
	unsigned char t[32];
	unsigned char buf[64 + 256];
	size_t tag_len = strlen(tag);
	crypto_hash_sha256(t, (const unsigned char *)tag, tag_len);
	if (data_len > 256) {
		unsigned char *heap = malloc(64 + data_len);
		if (!heap) {
			memset(out, 0, 32);
			return;
		}
		memcpy(heap, t, 32);
		memcpy(heap + 32, t, 32);
		memcpy(heap + 64, data, data_len);
		crypto_hash_sha256(out, heap, 64 + data_len);
		free(heap);
		return;
	}
	memcpy(buf, t, 32);
	memcpy(buf + 32, t, 32);
	if (data_len) {
		memcpy(buf + 64, data, data_len);
	}
	crypto_hash_sha256(out, buf, 64 + data_len);
}

void prime_blake2b_256(const unsigned char *in, size_t in_len, unsigned char out[32])
{
	crypto_generichash(out, 32, in, in_len, NULL, 0);
}

void prime_merkle_root(const unsigned char coinbase_txid[32],
		       const unsigned char branches[][32], unsigned n, unsigned char out[32])
{
	unsigned char acc[32];
	unsigned i;
	memcpy(acc, coinbase_txid, 32);
	for (i = 0; i < n; i++) {
		unsigned char combined[64];
		memcpy(combined, acc, 32);
		memcpy(combined + 32, branches[i], 32);
		prime_sha256d(combined, 64, acc);
	}
	memcpy(out, acc, 32);
}

void prime_target_for_pot(uint8_t exponent, unsigned char t[32])
{
	unsigned bit;
	memset(t, 0, 32);
	if (exponent >= 224) {
		t[31] = 1;
		return;
	}
	bit = 224u - (unsigned)exponent;
	t[31 - (bit / 8)] = (unsigned char)(1u << (bit % 8));
}

int prime_meets_target(const unsigned char hash[32], const unsigned char target[32])
{
	return memcmp(hash, target, 32) <= 0;
}

int prime_bits_to_target(uint32_t bits, unsigned char t[32])
{
	unsigned exp = bits >> 24;
	uint32_t mant = bits & 0x007fffffu;
	unsigned char m[3];
	unsigned i;
	size_t end;

	memset(t, 0, 32);
	if (bits & 0x00800000u) {
		return -1;
	}
	if (exp > 34) {
		return -1;
	}
	if (exp <= 3) {
		uint32_t v = mant >> (8u * (3u - exp));
		t[29] = (unsigned char)(v >> 16);
		t[30] = (unsigned char)(v >> 8);
		t[31] = (unsigned char)v;
		return 0;
	}
	end = 32u - (exp - 3u);
	m[0] = (unsigned char)(mant >> 16);
	m[1] = (unsigned char)(mant >> 8);
	m[2] = (unsigned char)mant;
	for (i = 0; i < 3; i++) {
		unsigned need = 3u - i;
		if (end >= need) {
			t[end - need] = m[i];
		} else if (m[i] != 0) {
			return -1;
		}
	}
	return 0;
}

static void wr32(unsigned char *p, uint32_t v)
{
	p[0] = (unsigned char)v;
	p[1] = (unsigned char)(v >> 8);
	p[2] = (unsigned char)(v >> 16);
	p[3] = (unsigned char)(v >> 24);
}

void prime_header_v2_serialize(unsigned char out[PRIME_HEADER_V2_SIZE],
			       uint32_t version, const unsigned char prev_block[32],
			       const unsigned char merkle_root[32], uint32_t time_on_wire,
			       uint32_t bits, uint32_t nonce, uint32_t nonce2, uint32_t nonce3,
			       const unsigned char extranonce[16], uint32_t time_offset,
			       uint16_t txcount, uint8_t flags, uint8_t xor_clear,
			       const unsigned char xor_key[16], int32_t height,
			       const unsigned char mm_rhs[32])
{
	unsigned char z16[16];
	unsigned char z32[32];
	memset(z16, 0, sizeof z16);
	memset(z32, 0, sizeof z32);
	wr32(out, (version & ~PRIME_V2_FLAG) | PRIME_V2_FLAG);
	memcpy(out + 4, prev_block, 32);
	memcpy(out + 36, merkle_root, 32);
	wr32(out + 68, time_on_wire);
	wr32(out + 72, bits);
	wr32(out + 76, nonce);
	wr32(out + 80, nonce2);
	wr32(out + 84, nonce3);
	memcpy(out + 88, extranonce ? extranonce : z16, 16);
	wr32(out + 104, time_offset);
	out[108] = (unsigned char)txcount;
	out[109] = (unsigned char)(txcount >> 8);
	out[110] = flags;
	out[111] = xor_clear;
	memcpy(out + 112, xor_key ? xor_key : z16, 16);
	wr32(out + 128, (uint32_t)height);
	memcpy(out + 132, mm_rhs ? mm_rhs : z32, 32);
}

size_t prime_encode_compact_size(uint64_t n, unsigned char out[9])
{
	if (n < 0xfd) {
		out[0] = (unsigned char)n;
		return 1;
	}
	if (n <= 0xffff) {
		out[0] = 0xfd;
		out[1] = (unsigned char)n;
		out[2] = (unsigned char)(n >> 8);
		return 3;
	}
	if (n <= 0xffffffffu) {
		out[0] = 0xfe;
		wr32(out + 1, (uint32_t)n);
		return 5;
	}
	out[0] = 0xff;
	{
		int i;
		for (i = 0; i < 8; i++) {
			out[1 + i] = (unsigned char)(n >> (8 * i));
		}
	}
	return 9;
}

static int rd_compact(const unsigned char *p, size_t n, size_t *off, uint64_t *out)
{
	unsigned char b;
	if (*off >= n) {
		return -1;
	}
	b = p[(*off)++];
	if (b < 0xfd) {
		*out = b;
		return 0;
	}
	if (b == 0xfd) {
		if (*off + 2 > n) {
			return -1;
		}
		*out = (uint64_t)p[*off] | ((uint64_t)p[*off + 1] << 8);
		*off += 2;
		return 0;
	}
	if (b == 0xfe) {
		if (*off + 4 > n) {
			return -1;
		}
		*out = (uint64_t)p[*off] | ((uint64_t)p[*off + 1] << 8)
			| ((uint64_t)p[*off + 2] << 16) | ((uint64_t)p[*off + 3] << 24);
		*off += 4;
		return 0;
	}
	if (*off + 8 > n) {
		return -1;
	}
	{
		uint64_t v = 0;
		int i;
		for (i = 0; i < 8; i++) {
			v |= (uint64_t)p[*off + i] << (8 * i);
		}
		*out = v;
		*off += 8;
	}
	return 0;
}

int prime_txid(const unsigned char *tx, size_t tx_len, unsigned char out[32])
{
	size_t off = 0;
	int has_witness = 0;
	uint64_t inputs, outputs, items;
	size_t body_start, body_end, lock_start;
	unsigned char *stripped;
	size_t stripped_len;
	uint64_t i, j;

	if (!tx || tx_len < 10) {
		return -1;
	}
	off = 4;
	if (off + 2 <= tx_len && tx[off] == 0x00 && tx[off + 1] == 0x01) {
		has_witness = 1;
		off += 2;
	}
	body_start = off;
	if (rd_compact(tx, tx_len, &off, &inputs) != 0 || inputs == 0) {
		return -1;
	}
	for (i = 0; i < inputs; i++) {
		uint64_t slen;
		if (off + 36 > tx_len) {
			return -1;
		}
		off += 36;
		if (rd_compact(tx, tx_len, &off, &slen) != 0 || off + slen + 4 > tx_len) {
			return -1;
		}
		off += (size_t)slen + 4;
	}
	if (rd_compact(tx, tx_len, &off, &outputs) != 0) {
		return -1;
	}
	for (i = 0; i < outputs; i++) {
		uint64_t slen;
		if (off + 8 > tx_len) {
			return -1;
		}
		off += 8;
		if (rd_compact(tx, tx_len, &off, &slen) != 0 || off + slen > tx_len) {
			return -1;
		}
		off += (size_t)slen;
	}
	body_end = off;
	if (has_witness) {
		for (i = 0; i < inputs; i++) {
			if (rd_compact(tx, tx_len, &off, &items) != 0) {
				return -1;
			}
			for (j = 0; j < items; j++) {
				uint64_t slen;
				if (rd_compact(tx, tx_len, &off, &slen) != 0 || off + slen > tx_len) {
					return -1;
				}
				off += (size_t)slen;
			}
		}
	}
	lock_start = off;
	if (off + 4 != tx_len) {
		return -1;
	}
	stripped_len = 4 + (body_end - body_start) + 4;
	stripped = malloc(stripped_len);
	if (!stripped) {
		return -1;
	}
	memcpy(stripped, tx, 4);
	memcpy(stripped + 4, tx + body_start, body_end - body_start);
	memcpy(stripped + 4 + (body_end - body_start), tx + lock_start, 4);
	prime_sha256d(stripped, stripped_len, out);
	free(stripped);
	return 0;
}

int prime_serialize_block(const unsigned char header[PRIME_HEADER_V2_SIZE],
			  const unsigned char *coinbase, size_t coinbase_len,
			  const unsigned char *const *txns, const size_t *txn_lens, size_t txn_n,
			  unsigned char **out, size_t *out_len)
{
	unsigned char cs[9];
	size_t csn = prime_encode_compact_size(txn_n + 1, cs);
	size_t n = PRIME_HEADER_V2_SIZE + csn + coinbase_len;
	size_t i, o;
	unsigned char *p;

	for (i = 0; i < txn_n; i++) {
		n += txn_lens[i];
	}
	p = malloc(n);
	if (!p) {
		return -1;
	}
	memcpy(p, header, PRIME_HEADER_V2_SIZE);
	o = PRIME_HEADER_V2_SIZE;
	memcpy(p + o, cs, csn);
	o += csn;
	memcpy(p + o, coinbase, coinbase_len);
	o += coinbase_len;
	for (i = 0; i < txn_n; i++) {
		memcpy(p + o, txns[i], txn_lens[i]);
		o += txn_lens[i];
	}
	*out = p;
	*out_len = n;
	return 0;
}

int prime_header_pow_hash_abw(const unsigned char prev_block[32], const unsigned char merkle_root[32],
			      uint32_t version, uint32_t time_on_wire, uint32_t bits,
			      uint32_t nonce, uint32_t nonce2, uint32_t nonce3, uint32_t time_offset,
			      const unsigned char extranonce[16], uint16_t txcount, uint8_t flags,
			      int32_t height, const unsigned char mm_rhs[32],
			      const unsigned char xor_key_in[16], uint8_t pot,
			      unsigned char result[32])
{
	unsigned char xor_key[16];
	unsigned char xor_key_hash[32];
	unsigned char mask[32];
	unsigned char prev_display[32];
	unsigned char h1d[119];
	unsigned char h1[32];
	unsigned char h2d[96];
	unsigned char h2[32];
	unsigned char ss[52];
	unsigned char hash1[32];
	unsigned char asic[80];
	unsigned char hash2[32];
	unsigned char hidden[32];
	size_t i;
	uint32_t complete_ver = version | 0x80000000u;

	if (xor_key_in) {
		memcpy(xor_key, xor_key_in, 16);
	} else {
		memset(xor_key, 0, sizeof xor_key);
	}
	prime_xor_key_hash(xor_key, xor_key_hash);

	memcpy(prev_display, prev_block, 32);
	for (i = 0; i < 16; i++) {
		unsigned char tmp = prev_display[i];
		prev_display[i] = prev_display[31 - i];
		prev_display[31 - i] = tmp;
	}

	i = 0;
	h1d[i++] = (unsigned char)complete_ver;
	h1d[i++] = (unsigned char)(complete_ver >> 8);
	h1d[i++] = (unsigned char)(complete_ver >> 16);
	h1d[i++] = (unsigned char)(complete_ver >> 24);
	memcpy(h1d + i, prev_display, 32);
	i += 32;
	h1d[i++] = (unsigned char)height;
	h1d[i++] = (unsigned char)((uint32_t)height >> 8);
	h1d[i++] = (unsigned char)((uint32_t)height >> 16);
	h1d[i++] = (unsigned char)((uint32_t)height >> 24);
	memcpy(h1d + i, merkle_root, 32);
	i += 32;
	h1d[i++] = (unsigned char)time_on_wire;
	h1d[i++] = (unsigned char)(time_on_wire >> 8);
	h1d[i++] = (unsigned char)(time_on_wire >> 16);
	h1d[i++] = (unsigned char)(time_on_wire >> 24);
	h1d[i++] = 0;
	h1d[i++] = (unsigned char)bits;
	h1d[i++] = (unsigned char)(bits >> 8);
	h1d[i++] = (unsigned char)(bits >> 16);
	h1d[i++] = (unsigned char)(bits >> 24);
	{
		uint32_t tc = txcount;
		h1d[i++] = (unsigned char)tc;
		h1d[i++] = (unsigned char)(tc >> 8);
		h1d[i++] = (unsigned char)(tc >> 16);
		h1d[i++] = (unsigned char)(tc >> 24);
	}
	h1d[i++] = flags;
	{
		int nz = 0;
		unsigned k;
		uint8_t clear;
		for (k = 0; k < 16; k++) {
			if (xor_key[k]) {
				nz = 1;
				break;
			}
		}
		clear = nz ? prime_abw_clear_bits(pot) : 0;
		h1d[i++] = clear;
	}
	memcpy(h1d + i, xor_key_hash, 32);
	i += 32;
	if (i != 119) {
		return -1;
	}
	prime_tagged_sha256("Bitcoin block header 1", h1d, 119, h1);

	memset(h2d, 0, sizeof h2d);
	memcpy(h2d, h1, 32);
	if (mm_rhs) {
		memcpy(h2d + 64, mm_rhs, 32);
	}
	prime_tagged_sha256("Merge-mining hook", h2d, 96, h2);

	memset(ss, 0, sizeof ss);
	memcpy(ss + 4, h2, 32);
	memcpy(ss + 36, extranonce, 16);
	prime_blake2b_256(ss, 52, hash1);

	prime_tagged_sha256("Bitcoin prevblock header, hashed", prev_display, 32, hidden);
	memset(hidden, 0, 6);

	memcpy(asic, hidden, 32);
	asic[32] = (unsigned char)nonce;
	asic[33] = (unsigned char)(nonce >> 8);
	asic[34] = (unsigned char)(nonce >> 16);
	asic[35] = (unsigned char)(nonce >> 24);
	asic[36] = (unsigned char)nonce2;
	asic[37] = (unsigned char)(nonce2 >> 8);
	asic[38] = (unsigned char)(nonce2 >> 16);
	asic[39] = (unsigned char)(nonce2 >> 24);
	asic[40] = (unsigned char)time_offset;
	asic[41] = (unsigned char)(time_offset >> 8);
	asic[42] = (unsigned char)(time_offset >> 16);
	asic[43] = (unsigned char)(time_offset >> 24);
	asic[44] = (unsigned char)nonce3;
	asic[45] = (unsigned char)(nonce3 >> 8);
	asic[46] = (unsigned char)(nonce3 >> 16);
	asic[47] = (unsigned char)(nonce3 >> 24);
	memcpy(asic + 48, hash1, 32);
	prime_blake2b_256(asic, 80, hash2);
	{
		uint8_t clear = prime_abw_clear_bits(pot);
		unsigned k;
		prime_xor_mask(xor_key, clear, mask);
		for (k = 0; k < 32; k++) {
			result[k] = hash2[k] ^ mask[k];
		}
	}
	(void)flags;
	return 0;
}

int prime_header_pow_hash(const unsigned char prev_block[32], const unsigned char merkle_root[32],
			  uint32_t version, uint32_t time_on_wire, uint32_t bits,
			  uint32_t nonce, uint32_t nonce2, uint32_t nonce3, uint32_t time_offset,
			  const unsigned char extranonce[16], uint16_t txcount, uint8_t flags,
			  int32_t height, const unsigned char mm_rhs[32], unsigned char result[32])
{
	unsigned char z[16];
	memset(z, 0, sizeof z);
	return prime_header_pow_hash_abw(prev_block, merkle_root, version, time_on_wire, bits,
					 nonce, nonce2, nonce3, time_offset, extranonce, txcount,
					 flags, height, mm_rhs, z, 0, result);
}
