/* Bitcoin mainnet address to scriptPubKey.
 * Supports Base58Check P2PKH/P2SH plus Bech32/Bech32m v0/v1 witness
 * outputs. Other types stay unpaid and fall through to the pool remainder.
 * Copyright (C) Blockvase contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#include "prime.h"

#include <string.h>

static const char *BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
static const char *BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static int bech32_val(char c)
{
	const char *p;
	if (c >= 'A' && c <= 'Z') {
		c = (char)(c - 'A' + 'a');
	}
	p = strchr(BECH32, c);
	return p ? (int)(p - BECH32) : -1;
}

static uint32_t polymod(const unsigned char *v, size_t n)
{
	uint32_t c = 1;
	size_t i;
	for (i = 0; i < n; i++) {
		uint8_t c0 = (uint8_t)(c >> 25);
		c = ((c & 0x1ffffffu) << 5) ^ v[i];
		if (c0 & 1) {
			c ^= 0x3b6a57b2u;
		}
		if (c0 & 2) {
			c ^= 0x26508e6du;
		}
		if (c0 & 4) {
			c ^= 0x1ea119fau;
		}
		if (c0 & 8) {
			c ^= 0x3d4233ddu;
		}
		if (c0 & 16) {
			c ^= 0x2a1462b3u;
		}
	}
	return c;
}

static void hrp_expand(const char *hrp, unsigned char *out, size_t *out_len)
{
	size_t i, n = strlen(hrp);
	for (i = 0; i < n; i++) {
		out[i] = (unsigned char)(hrp[i] >> 5);
	}
	out[n] = 0;
	for (i = 0; i < n; i++) {
		out[n + 1 + i] = (unsigned char)(hrp[i] & 31);
	}
	*out_len = n * 2 + 1;
}

static int base58_val(char c)
{
	const char *p = strchr(BASE58, c);
	return p ? (int)(p - BASE58) : -1;
}

static int base58_script(const char *addr, unsigned char *out, size_t *out_len, size_t max_len)
{
	unsigned char num[32];
	unsigned char payload[25];
	unsigned char check[32];
	size_t i, j, zeros = 0, start, payload_len;

	memset(num, 0, sizeof num);
	for (i = 0; addr[i]; i++) {
		int v = base58_val(addr[i]);
		unsigned carry;
		if (v < 0) {
			return -1;
		}
		carry = (unsigned)v;
		for (j = sizeof num; j > 0; j--) {
			carry += 58u * num[j - 1];
			num[j - 1] = (unsigned char)(carry & 0xffu);
			carry >>= 8;
		}
		if (carry) {
			return -1;
		}
	}
	while (addr[zeros] == '1') {
		zeros++;
	}
	for (start = 0; start < sizeof num && num[start] == 0; start++) {
	}
	payload_len = zeros + sizeof num - start;
	if (payload_len != sizeof payload) {
		return -1;
	}
	memset(payload, 0, zeros);
	memcpy(payload + zeros, num + start, sizeof num - start);
	prime_sha256d(payload, 21, check);
	if (memcmp(check, payload + 21, 4) != 0) {
		return -1;
	}
	if (payload[0] == 0x00) {
		if (max_len < 25) {
			return -1;
		}
		out[0] = 0x76;
		out[1] = 0xa9;
		out[2] = 0x14;
		memcpy(out + 3, payload + 1, 20);
		out[23] = 0x88;
		out[24] = 0xac;
		*out_len = 25;
		return 0;
	}
	if (payload[0] == 0x05) {
		if (max_len < 23) {
			return -1;
		}
		out[0] = 0xa9;
		out[1] = 0x14;
		memcpy(out + 2, payload + 1, 20);
		out[22] = 0x87;
		*out_len = 23;
		return 0;
	}
	return -1;
}

int prime_address_script(const char *addr, unsigned char *out, size_t *out_len, size_t max_len)
{
	char lower[128];
	char hrp[8];
	unsigned char values[128];
	unsigned char chk[160];
	size_t i, n = 0, hrp_len = 0, data_n, chk_n;
	int sep = -1, witver;
	unsigned char bytes[40];
	size_t bitbuf = 0, bits = 0, bo = 0;
	uint32_t want;

	if (!addr || !out || !out_len) {
		return -1;
	}
	if (addr[0] == '1' || addr[0] == '3') {
		return base58_script(addr, out, out_len, max_len);
	}
	for (i = 0; addr[i] && i + 1 < sizeof lower; i++) {
		char c = addr[i];
		if (c >= 'A' && c <= 'Z') {
			c = (char)(c - 'A' + 'a');
		}
		lower[i] = c;
		if (c == '1') {
			sep = (int)i;
		}
	}
	lower[i] = 0;
	if (sep < 1 || sep > 4) {
		return -1;
	}
	memcpy(hrp, lower, (size_t)sep);
	hrp[sep] = 0;
	if (strcmp(hrp, "bc") != 0) {
		return -1;
	}
	for (i = (size_t)sep + 1; lower[i]; i++) {
		int v = bech32_val(lower[i]);
		if (v < 0 || n >= sizeof values) {
			return -1;
		}
		values[n++] = (unsigned char)v;
	}
	if (n < 7) {
		return -1;
	}
	hrp_expand(hrp, chk, &hrp_len);
	memcpy(chk + hrp_len, values, n);
	chk_n = hrp_len + n;
	witver = values[0];
	if (n < 8) {
		return -1;
	}
	data_n = n - 7;
	if (data_n < 1) {
		return -1;
	}
	want = (witver == 0) ? 1u : 0x2bc830a3u;
	if (polymod(chk, chk_n) != want) {
		return -1;
	}
	bitbuf = 0;
	bits = 0;
	bo = 0;
	for (i = 1; i < n - 6; i++) {
		bitbuf = (bitbuf << 5) | values[i];
		bits += 5;
		if (bits >= 8) {
			bits -= 8;
			if (bo >= sizeof bytes) {
				return -1;
			}
			bytes[bo++] = (unsigned char)(bitbuf >> bits);
		}
	}
	if (witver == 0 && bo == 20) {
		if (max_len < 22) {
			return -1;
		}
		out[0] = 0x00;
		out[1] = 0x14;
		memcpy(out + 2, bytes, 20);
		*out_len = 22;
		return 0;
	}
	if (witver == 0 && bo == 32) {
		if (max_len < 34) {
			return -1;
		}
		out[0] = 0x00;
		out[1] = 0x20;
		memcpy(out + 2, bytes, 32);
		*out_len = 34;
		return 0;
	}
	if (witver == 1 && bo == 32) {
		if (max_len < 34) {
			return -1;
		}
		out[0] = 0x51;
		out[1] = 0x20;
		memcpy(out + 2, bytes, 32);
		*out_len = 34;
		return 0;
	}
	return -1;
}
