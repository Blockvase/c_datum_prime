/* Translated from RATUM core/src/datum/handshake.rs and messages.rs by iohzrd.
 * Copyright (C) iohzrd and RATUM contributors
 * Copyright (C) Blockvase contributors (C translation)
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#include "prime.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const unsigned char DRS_MARKER[4] = { 'D', 'R', 'S', 0x01 };

int prime_open_hello(const prime_header *header, const unsigned char *payload, size_t payload_len,
		     const prime_keypairs *pool, prime_hello *out)
{
	unsigned char *plain = NULL;
	size_t plain_len;
	const unsigned char *signed_body;
	size_t signed_len;
	const unsigned char *sig;
	const unsigned char *rest;
	const unsigned char *after;
	const unsigned char *nul;
	size_t ua_len;
	int rc = -1;

	if (header->proto_cmd != PRIME_CMD_HELLO_OR_PING
	    || !header->is_signed
	    || !header->is_encrypted_pubkey
	    || header->is_encrypted_channel) {
		fprintf(stderr, "prime: bad hello header\n");
		return -1;
	}
	if (payload_len < crypto_box_SEALBYTES) {
		return -1;
	}
	plain_len = payload_len - crypto_box_SEALBYTES;
	plain = malloc(plain_len);
	if (!plain) {
		return -1;
	}
	if (crypto_box_seal_open(plain, payload, payload_len, pool->box_pk, pool->box_sk) != 0) {
		fprintf(stderr, "prime: hello unseal failed\n");
		goto done;
	}
	if (plain_len < PRIME_KEYS_LEN + crypto_sign_BYTES) {
		goto done;
	}
	signed_len = plain_len - crypto_sign_BYTES;
	signed_body = plain;
	sig = plain + signed_len;
	if (crypto_sign_verify_detached(sig, signed_body, signed_len, signed_body) != 0) {
		fprintf(stderr, "prime: hello signature failed\n");
		goto done;
	}

	memset(out, 0, sizeof *out);
	memcpy(out->client_sign_pk, signed_body, 32);
	memcpy(out->client_box_pk, signed_body + 32, 32);
	memcpy(out->session_sign_pk, signed_body + 64, 32);
	memcpy(out->session_box_pk, signed_body + 96, 32);

	rest = signed_body + PRIME_KEYS_LEN;
	nul = memchr(rest, 0, signed_len - PRIME_KEYS_LEN);
	if (!nul) {
		fprintf(stderr, "prime: hello has no UA terminator\n");
		goto done;
	}
	ua_len = (size_t)(nul - rest);
	if (ua_len > PRIME_MAX_UA) {
		ua_len = PRIME_MAX_UA;
	}
	memcpy(out->user_agent, rest, ua_len);
	out->user_agent[ua_len] = 0;

	after = nul + 1;
	if ((size_t)(signed_body + signed_len - after) < 5) {
		goto done;
	}
	if (after[0] != PRIME_STRUCT_END) {
		fprintf(stderr, "prime: hello missing 0xFE after UA\n");
		goto done;
	}
	out->nk = (uint32_t)after[1] | ((uint32_t)after[2] << 8)
		| ((uint32_t)after[3] << 16) | ((uint32_t)after[4] << 24);

	{
		const unsigned char *tail = after + 5;
		size_t tail_len = (size_t)(signed_body + signed_len - tail);
		if (tail_len >= 5 && memcmp(tail, DRS_MARKER, 4) == 0) {
			out->generation = PRIME_GEN_V3;
			if (tail[4] != 0) {
				if (tail_len < 5 + PRIME_RESUME_TOKEN_LEN) {
					fprintf(stderr, "prime: DRS resume flag without token\n");
					goto done;
				}
				out->resume_present = true;
				memcpy(out->resume_token, tail + 5, PRIME_RESUME_TOKEN_LEN);
			}
		} else {
			out->generation = PRIME_GEN_V1;
		}
	}
	rc = 0;
done:
	if (plain) {
		sodium_memzero(plain, plain_len);
		free(plain);
	}
	return rc;
}

int prime_accept(const prime_hello *hello, const prime_keypairs *pool, const char *motd,
		 unsigned char **wire, size_t *wire_len, prime_session *session)
{
	unsigned char session_sign_pk[crypto_sign_PUBLICKEYBYTES];
	unsigned char session_sign_sk[crypto_sign_SECRETKEYBYTES];
	unsigned char session_box_pk[crypto_box_PUBLICKEYBYTES];
	unsigned char session_box_sk[crypto_box_SECRETKEYBYTES];
	unsigned char *body = NULL;
	unsigned char *sealed = NULL;
	size_t motd_len;
	size_t body_len;
	size_t sealed_len;
	size_t i = 0;
	unsigned char sig[crypto_sign_BYTES];
	uint32_t cts, stc;
	prime_header header;
	prime_ratchet tx;
	int rc = -1;

	*wire = NULL;
	*wire_len = 0;
	memset(session, 0, sizeof *session);

	if (!motd) {
		motd = "";
	}
	motd_len = strlen(motd);
	if (motd_len > PRIME_MAX_MOTD) {
		motd_len = PRIME_MAX_MOTD;
	}

	if (crypto_sign_keypair(session_sign_pk, session_sign_sk) != 0) {
		return -1;
	}
	if (crypto_box_keypair(session_box_pk, session_box_sk) != 0) {
		return -1;
	}

	body_len = PRIME_KEYS_LEN + 64 + motd_len + 1;
	body = malloc(body_len + crypto_sign_BYTES);
	if (!body) {
		goto done;
	}
	memcpy(body + i, hello->client_sign_pk, 32); i += 32;
	memcpy(body + i, hello->client_box_pk, 32); i += 32;
	memcpy(body + i, hello->session_sign_pk, 32); i += 32;
	memcpy(body + i, hello->session_box_pk, 32); i += 32;
	memcpy(body + i, session_sign_pk, 32); i += 32;
	memcpy(body + i, session_box_pk, 32); i += 32;
	memcpy(body + i, motd, motd_len); i += motd_len;
	body[i++] = 0;
	if (i != body_len) {
		goto done;
	}
	if (crypto_sign_detached(sig, NULL, body, body_len, pool->sign_sk) != 0) {
		goto done;
	}
	memcpy(body + body_len, sig, crypto_sign_BYTES);
	body_len += crypto_sign_BYTES;

	sealed_len = body_len + crypto_box_SEALBYTES;
	if (sealed_len > PRIME_MAX_CMD_LEN) {
		goto done;
	}
	sealed = malloc(sealed_len);
	if (!sealed) {
		goto done;
	}
	if (crypto_box_seal(sealed, body, body_len, hello->session_box_pk) != 0) {
		goto done;
	}

	prime_header_keys_from_nk(hello->nk, &cts, &stc);
	prime_ratchet_init(&tx, stc);
	memset(&header, 0, sizeof header);
	header.cmd_len = (uint32_t)sealed_len;
	header.is_signed = true;
	header.is_encrypted_pubkey = true;
	header.proto_cmd = PRIME_CMD_HANDSHAKE_RESPONSE;

	*wire_len = 4 + sealed_len;
	*wire = malloc(*wire_len);
	if (!*wire) {
		goto done;
	}
	prime_ratchet_mask(&tx, &header, *wire);
	memcpy(*wire + 4, sealed, sealed_len);

	if (crypto_box_beforenm(session->precomp, hello->session_box_pk, session_box_sk) != 0) {
		goto done;
	}
	prime_derive_nonces(hello->nk, hello->session_sign_pk, session->tx_nonce, session->rx_nonce);
	session->tx_headers = tx;
	prime_ratchet_init(&session->rx_headers, cts);
	memcpy(session->session_sign_sk, session_sign_sk, sizeof session_sign_sk);
	memcpy(session->session_sign_pk, session_sign_pk, sizeof session_sign_pk);
	memcpy(session->peer_session_sign_pk, hello->session_sign_pk, 32);
	session->ready = true;
	rc = 0;
done:
	if (body) {
		sodium_memzero(body, body_len);
		free(body);
	}
	free(sealed);
	sodium_memzero(session_sign_sk, sizeof session_sign_sk);
	sodium_memzero(session_box_sk, sizeof session_box_sk);
	if (rc != 0 && *wire) {
		free(*wire);
		*wire = NULL;
		*wire_len = 0;
	}
	return rc;
}

int prime_session_encrypt(prime_session *s, uint8_t proto_cmd, const unsigned char *payload,
			  size_t payload_len, bool sign, unsigned char **wire, size_t *wire_len)
{
	unsigned char *plain = NULL;
	unsigned char *ct = NULL;
	size_t plain_len;
	size_t ct_len;
	prime_header header;
	int rc = -1;

	*wire = NULL;
	*wire_len = 0;
	if (!s->ready) {
		return -1;
	}

	if (sign) {
		plain_len = payload_len + crypto_sign_BYTES;
		plain = malloc(plain_len);
		if (!plain) {
			return -1;
		}
		memcpy(plain, payload, payload_len);
		if (crypto_sign_detached(plain + payload_len, NULL, payload, payload_len,
					 s->session_sign_sk) != 0) {
			goto done;
		}
	} else {
		plain_len = payload_len;
		plain = malloc(plain_len ? plain_len : 1);
		if (!plain) {
			return -1;
		}
		if (payload_len) {
			memcpy(plain, payload, payload_len);
		}
	}

	ct_len = plain_len + crypto_box_MACBYTES;
	if (ct_len > PRIME_MAX_CMD_LEN) {
		goto done;
	}
	ct = malloc(ct_len);
	if (!ct) {
		goto done;
	}
	if (crypto_box_easy_afternm(ct, plain, plain_len, s->tx_nonce, s->precomp) != 0) {
		goto done;
	}
	prime_increment_nonce(s->tx_nonce);

	memset(&header, 0, sizeof header);
	header.cmd_len = (uint32_t)ct_len;
	header.is_signed = sign;
	header.is_encrypted_channel = true;
	header.proto_cmd = proto_cmd;

	*wire_len = 4 + ct_len;
	*wire = malloc(*wire_len);
	if (!*wire) {
		goto done;
	}
	prime_ratchet_mask(&s->tx_headers, &header, *wire);
	memcpy(*wire + 4, ct, ct_len);
	rc = 0;
done:
	if (plain) {
		sodium_memzero(plain, plain_len);
		free(plain);
	}
	free(ct);
	if (rc != 0 && *wire) {
		free(*wire);
		*wire = NULL;
		*wire_len = 0;
	}
	return rc;
}

int prime_session_decrypt(prime_session *s, const prime_header *header,
			  const unsigned char *ciphertext, size_t ciphertext_len,
			  unsigned char **plain, size_t *plain_len)
{
	unsigned char *buf = NULL;
	size_t buf_len;
	int rc = -1;

	*plain = NULL;
	*plain_len = 0;
	if (!s->ready) {
		return -1;
	}
	if (!header->is_encrypted_channel || header->is_encrypted_pubkey) {
		return -1;
	}
	if (ciphertext_len < crypto_box_MACBYTES) {
		return -1;
	}
	buf_len = ciphertext_len - crypto_box_MACBYTES;
	buf = malloc(buf_len ? buf_len : 1);
	if (!buf) {
		return -1;
	}
	if (crypto_box_open_easy_afternm(buf, ciphertext, ciphertext_len, s->rx_nonce, s->precomp) != 0) {
		goto done;
	}
	prime_increment_nonce(s->rx_nonce);
	if (header->is_signed) {
		if (buf_len < crypto_sign_BYTES) {
			goto done;
		}
		if (crypto_sign_verify_detached(buf + buf_len - crypto_sign_BYTES, buf,
						buf_len - crypto_sign_BYTES,
						s->peer_session_sign_pk) != 0) {
			goto done;
		}
		buf_len -= crypto_sign_BYTES;
	}
	*plain = buf;
	*plain_len = buf_len;
	buf = NULL;
	rc = 0;
done:
	free(buf);
	return rc;
}

static int is_power_of_two_u64(uint64_t v)
{
	return v != 0 && (v & (v - 1)) == 0;
}

static void put_u64le(unsigned char *p, uint64_t v)
{
	int i;
	for (i = 0; i < 8; i++) {
		p[i] = (unsigned char)(v >> (8 * i));
	}
}

static void put_u32le(unsigned char *p, uint32_t v)
{
	p[0] = (unsigned char)(v);
	p[1] = (unsigned char)(v >> 8);
	p[2] = (unsigned char)(v >> 16);
	p[3] = (unsigned char)(v >> 24);
}

int prime_encode_config_v1(const prime_config_opts *opt, unsigned char **out, size_t *out_len)
{
	size_t tag_len;
	size_t n;
	unsigned char *p;

	*out = NULL;
	*out_len = 0;
	if (!opt || !opt->coinbase_tag) {
		return -1;
	}
	tag_len = strlen(opt->coinbase_tag);
	if (opt->payout_script_len > PRIME_MAX_PAYOUT_SCRIPT
	    || tag_len > PRIME_MAX_COINBASE_TAG
	    || !is_power_of_two_u64(opt->min_difficulty)) {
		return -1;
	}
	n = 2 + 1 + opt->payout_script_len + 4 + 1 + tag_len + 8 + 2;
	p = malloc(n);
	if (!p) {
		return -1;
	}
	p[0] = PRIME_MINING_CONFIG;
	p[1] = PRIME_CONFIG_V1;
	p[2] = (unsigned char)opt->payout_script_len;
	memcpy(p + 3, opt->payout_script, opt->payout_script_len);
	put_u32le(p + 3 + opt->payout_script_len, (uint32_t)opt->prime_id);
	p[3 + opt->payout_script_len + 4] = (unsigned char)tag_len;
	memcpy(p + 3 + opt->payout_script_len + 5, opt->coinbase_tag, tag_len);
	put_u64le(p + 3 + opt->payout_script_len + 5 + tag_len, opt->min_difficulty);
	p[n - 2] = 0;
	p[n - 1] = PRIME_STRUCT_END;
	*out = p;
	*out_len = n;
	return 0;
}

int prime_encode_config_v3(const prime_config_opts *opt, const unsigned char resume_token[PRIME_RESUME_TOKEN_LEN],
			   unsigned char **out, size_t *out_len)
{
	size_t tag_len;
	size_t n;
	unsigned char *p;
	size_t i;

	*out = NULL;
	*out_len = 0;
	if (!opt || !opt->coinbase_tag || !resume_token) {
		return -1;
	}
	tag_len = strlen(opt->coinbase_tag);
	if (opt->payout_script_len > PRIME_MAX_PAYOUT_SCRIPT
	    || tag_len > PRIME_MAX_COINBASE_TAG
	    || !is_power_of_two_u64(opt->min_difficulty)) {
		return -1;
	}
	n = 2 + 1 + opt->payout_script_len + 8 + PRIME_RESUME_TOKEN_LEN + 1 + tag_len + 8 + 2;
	if (opt->bulk_framing) {
		n += 4;
	}
	p = malloc(n);
	if (!p) {
		return -1;
	}
	i = 0;
	p[i++] = PRIME_MINING_CONFIG;
	p[i++] = PRIME_CONFIG_V3;
	p[i++] = (unsigned char)opt->payout_script_len;
	memcpy(p + i, opt->payout_script, opt->payout_script_len);
	i += opt->payout_script_len;
	put_u64le(p + i, opt->prime_id);
	i += 8;
	memcpy(p + i, resume_token, PRIME_RESUME_TOKEN_LEN);
	i += PRIME_RESUME_TOKEN_LEN;
	p[i++] = (unsigned char)tag_len;
	memcpy(p + i, opt->coinbase_tag, tag_len);
	i += tag_len;
	put_u64le(p + i, opt->min_difficulty);
	i += 8;
	p[i++] = opt->abw_disabled ? PRIME_CONFIG_FLAG_ABW_DISABLED : 0;
	p[i++] = PRIME_STRUCT_END;
	if (opt->bulk_framing) {
		p[i++] = 'D';
		p[i++] = 'B';
		p[i++] = 'F';
		p[i++] = 0x01;
	}
	if (i != n) {
		free(p);
		return -1;
	}
	*out = p;
	*out_len = n;
	return 0;
}

void prime_new_resume_token(uint64_t prime_id, unsigned char token[PRIME_RESUME_TOKEN_LEN])
{
	put_u64le(token, prime_id);
	randombytes_buf(token + 8, PRIME_RESUME_TOKEN_LEN - 8);
}
