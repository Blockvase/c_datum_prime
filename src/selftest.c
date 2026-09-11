/* Translated from RATUM core/src/datum/framing.rs and handshake.rs tests by iohzrd.
 * Copyright (C) iohzrd and RATUM contributors
 * Copyright (C) Blockvase contributors (C translation)
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#include "prime.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int expect_hex(const char *what, const unsigned char *bin, size_t len, const char *want)
{
	char got[512];
	if (len * 2 + 1 > sizeof got) {
		fprintf(stderr, "selftest: %s hex too long\n", what);
		return -1;
	}
	prime_hex_encode(bin, len, got, sizeof got);
	if (strcmp(got, want) != 0) {
		fprintf(stderr, "selftest: %s\n  got  %s\n  want %s\n", what, got, want);
		return -1;
	}
	return 0;
}

static int test_feedback(void)
{
	struct {
		uint32_t in;
		uint32_t want;
	} cases[] = {
		{ 0x00000000u, 0x74a55cf6u },
		{ 0x00000001u, 0xab98b5deu },
		{ 0x0000002au, 0xd545aea2u },
		{ 0xdc871829u, 0x88e1697du },
		{ 0xffffffffu, 0x8541e231u },
		{ 0x12345678u, 0x2bbbe280u },
		{ 0xb10cfeedu, 0xd9dc5e65u },
	};
	size_t i;
	for (i = 0; i < sizeof cases / sizeof cases[0]; i++) {
		uint32_t got = prime_feedback(cases[i].in);
		if (got != cases[i].want) {
			fprintf(stderr, "selftest: feedback(%08x) got %08x want %08x\n",
				cases[i].in, got, cases[i].want);
			return -1;
		}
	}
	return 0;
}

static int test_headers(void)
{
	struct {
		prime_header h;
		const char *raw;
		const char *xored;
	} cases[5];
	size_t i;

	memset(cases, 0, sizeof cases);
	cases[0].h.cmd_len = 42;
	cases[0].h.is_signed = true;
	cases[0].h.is_encrypted_pubkey = true;
	cases[0].h.proto_cmd = 1;
	cases[0].raw = "2a00000b";
	cases[0].xored = "031887d7";

	cases[1].h.cmd_len = 1;
	cases[1].h.is_encrypted_channel = true;
	cases[1].h.proto_cmd = 5;
	cases[1].raw = "0100002c";
	cases[1].xored = "281887f0";

	cases[2].h.cmd_len = 4194303;
	cases[2].h.is_signed = true;
	cases[2].h.is_encrypted_pubkey = true;
	cases[2].h.is_encrypted_channel = true;
	cases[2].h.proto_cmd = 31;
	cases[2].raw = "ffff3fff";
	cases[2].xored = "d6e7b823";

	cases[3].raw = "00000000";
	cases[3].xored = "291887dc";

	cases[4].h.cmd_len = 1234567;
	cases[4].h.is_encrypted_pubkey = true;
	cases[4].h.proto_cmd = 7;
	cases[4].raw = "87d6123a";
	cases[4].xored = "aece95e6";

	for (i = 0; i < 5; i++) {
		unsigned char raw[4];
		unsigned char masked[4];
		prime_header back;
		prime_ratchet r;
		prime_header_to_bytes(&cases[i].h, raw);
		if (expect_hex("header raw", raw, 4, cases[i].raw) != 0) {
			return -1;
		}
		prime_header_from_bytes(raw, &back);
		if (back.cmd_len != cases[i].h.cmd_len
		    || back.is_signed != cases[i].h.is_signed
		    || back.is_encrypted_pubkey != cases[i].h.is_encrypted_pubkey
		    || back.is_encrypted_channel != cases[i].h.is_encrypted_channel
		    || back.proto_cmd != cases[i].h.proto_cmd) {
			fprintf(stderr, "selftest: header roundtrip %zu failed\n", i);
			return -1;
		}
		prime_ratchet_hello(&r);
		prime_ratchet_mask(&r, &cases[i].h, masked);
		if (expect_hex("header xor hello", masked, 4, cases[i].xored) != 0) {
			return -1;
		}
	}
	return 0;
}

static int test_nk_and_nonces(void)
{
	uint32_t cts, stc;
	unsigned char pk[32];
	unsigned char recv[PRIME_NONCE_LEN];
	unsigned char send[PRIME_NONCE_LEN];
	unsigned char n[PRIME_NONCE_LEN];
	int i;

	prime_header_keys_from_nk(0x9abcdef0u, &cts, &stc);
	if (cts != 0x62aaf25cu || stc != 0x0cef5178u) {
		fprintf(stderr, "selftest: header keys from nk mismatch (%08x %08x)\n", cts, stc);
		return -1;
	}
	for (i = 0; i < 32; i++) {
		pk[i] = (unsigned char)i;
	}
	prime_derive_nonces(0x9abcdef0u, pk, recv, send);
	if (expect_hex("client_receiver", recv, PRIME_NONCE_LEN, "58d38abdfecc665c2cd520e1e970b81eb7f3cdd3f3bb1703") != 0) {
		return -1;
	}
	if (expect_hex("client_sender", send, PRIME_NONCE_LEN, "0f84ddeaa99b310b7b8277b6be27ef49e0a49a84a4ec4054") != 0) {
		return -1;
	}

	memset(n, 0, sizeof n);
	prime_increment_nonce(n);
	if (expect_hex("nonce +1", n, PRIME_NONCE_LEN, "010000000000000000000000000000000000000000000000") != 0) {
		return -1;
	}
	memset(n, 0, sizeof n);
	n[0] = n[1] = n[2] = n[3] = 0xff;
	prime_increment_nonce(n);
	if (expect_hex("nonce wrap word", n, PRIME_NONCE_LEN, "000000000100000000000000000000000000000000000000") != 0) {
		return -1;
	}
	return 0;
}

static int build_client_hello(const prime_keypairs *pool, const prime_keypairs *long_term,
			      const prime_keypairs *sess, uint32_t nk, int with_drs,
			      unsigned char **wire, size_t *wire_len)
{
	unsigned char body[512];
	unsigned char sealed[512 + crypto_box_SEALBYTES];
	size_t i = 0;
	size_t sealed_len;
	const char *ua = "v0.4.1-beta/deadbeef";
	prime_header h;
	prime_ratchet r;
	unsigned char sig[crypto_sign_BYTES];

	memcpy(body + i, long_term->sign_pk, 32); i += 32;
	memcpy(body + i, long_term->box_pk, 32); i += 32;
	memcpy(body + i, sess->sign_pk, 32); i += 32;
	memcpy(body + i, sess->box_pk, 32); i += 32;
	memcpy(body + i, ua, strlen(ua)); i += strlen(ua);
	body[i++] = 0;
	body[i++] = PRIME_STRUCT_END;
	body[i++] = (unsigned char)(nk);
	body[i++] = (unsigned char)(nk >> 8);
	body[i++] = (unsigned char)(nk >> 16);
	body[i++] = (unsigned char)(nk >> 24);
	if (with_drs) {
		memcpy(body + i, "DRS\x01", 4); i += 4;
		body[i++] = 0;
	}
	memset(body + i, 0xAB, 17); i += 17;
	if (crypto_sign_detached(sig, NULL, body, i, long_term->sign_sk) != 0) {
		return -1;
	}
	memcpy(body + i, sig, crypto_sign_BYTES);
	i += crypto_sign_BYTES;
	if (crypto_box_seal(sealed, body, i, pool->box_pk) != 0) {
		return -1;
	}
	sealed_len = i + crypto_box_SEALBYTES;
	memset(&h, 0, sizeof h);
	h.cmd_len = (uint32_t)sealed_len;
	h.is_signed = true;
	h.is_encrypted_pubkey = true;
	h.proto_cmd = PRIME_CMD_HELLO_OR_PING;
	*wire_len = 4 + sealed_len;
	*wire = malloc(*wire_len);
	if (!*wire) {
		return -1;
	}
	prime_ratchet_hello(&r);
	prime_ratchet_mask(&r, &h, *wire);
	memcpy(*wire + 4, sealed, sealed_len);
	return 0;
}

static int test_handshake_and_config(void)
{
	prime_keypairs pool, long_term, sess;
	unsigned char *hello_wire = NULL;
	unsigned char *resp_wire = NULL;
	unsigned char *cfg = NULL;
	unsigned char *cfg_wire = NULL;
	unsigned char *plain = NULL;
	size_t hello_len, resp_len, cfg_len, cfg_wire_len, plain_len;
	prime_ratchet rx;
	prime_header h;
	prime_hello hello;
	prime_session session;
	prime_config_opts opt;
	unsigned char token[PRIME_RESUME_TOKEN_LEN];
	unsigned char payout[22];
	const char *motd = "c-datum-prime selftest";
	uint32_t nk = 0x11223344u;
	int rc = -1;

	memset(payout, 0, sizeof payout);
	payout[0] = 0x00;
	payout[1] = 0x14;

	if (prime_keys_generate(&pool) != 0
	    || prime_keys_generate(&long_term) != 0
	    || prime_keys_generate(&sess) != 0) {
		fprintf(stderr, "selftest: keygen failed\n");
		return -1;
	}
	if (build_client_hello(&pool, &long_term, &sess, nk, 1, &hello_wire, &hello_len) != 0) {
		fprintf(stderr, "selftest: build hello failed\n");
		goto done;
	}
	prime_ratchet_hello(&rx);
	prime_ratchet_unmask(&rx, hello_wire, &h);
	if (prime_open_hello(&h, hello_wire + 4, hello_len - 4, &pool, &hello) != 0) {
		fprintf(stderr, "selftest: open_hello failed\n");
		goto done;
	}
	if (hello.generation != PRIME_GEN_V3 || hello.nk != nk
	    || memcmp(hello.session_sign_pk, sess.sign_pk, 32) != 0
	    || strcmp(hello.user_agent, "v0.4.1-beta/deadbeef") != 0) {
		fprintf(stderr, "selftest: hello fields mismatch (gen=%d nk=%08x ua=%s)\n",
			(int)hello.generation, hello.nk, hello.user_agent);
		goto done;
	}
	if (prime_accept(&hello, &pool, motd, &resp_wire, &resp_len, &session) != 0) {
		fprintf(stderr, "selftest: accept failed\n");
		goto done;
	}

	{
		uint32_t cts, stc;
		unsigned char opened[2048];
		size_t opened_len;
		prime_ratchet client_rx;
		prime_header rh;
		prime_header_keys_from_nk(nk, &cts, &stc);
		prime_ratchet_init(&client_rx, stc);
		prime_ratchet_unmask(&client_rx, resp_wire, &rh);
		if (rh.proto_cmd != PRIME_CMD_HANDSHAKE_RESPONSE
		    || !rh.is_signed || !rh.is_encrypted_pubkey
		    || rh.cmd_len + 4 != resp_len) {
			fprintf(stderr, "selftest: handshake response header bad\n");
			goto done;
		}
		if (crypto_box_seal_open(opened, resp_wire + 4, rh.cmd_len, sess.box_pk, sess.box_sk) != 0) {
			fprintf(stderr, "selftest: client could not unseal handshake\n");
			goto done;
		}
		opened_len = rh.cmd_len - crypto_box_SEALBYTES;
		if (opened_len < crypto_sign_BYTES) {
			goto done;
		}
		if (crypto_sign_verify_detached(opened + opened_len - crypto_sign_BYTES, opened,
						opened_len - crypto_sign_BYTES, pool.sign_pk) != 0) {
			fprintf(stderr, "selftest: handshake sig failed on client\n");
			goto done;
		}
		opened_len -= crypto_sign_BYTES;
		if (opened_len < 192 + strlen(motd) + 1) {
			fprintf(stderr, "selftest: handshake body short\n");
			goto done;
		}
		if (memcmp(opened, long_term.sign_pk, 32) != 0
		    || memcmp(opened + 32, long_term.box_pk, 32) != 0
		    || memcmp(opened + 64, sess.sign_pk, 32) != 0
		    || memcmp(opened + 96, sess.box_pk, 32) != 0) {
			fprintf(stderr, "selftest: handshake did not echo client keys\n");
			goto done;
		}
		if (strcmp((char *)opened + 192, motd) != 0) {
			fprintf(stderr, "selftest: MOTD mismatch\n");
			goto done;
		}
	}

	memset(&opt, 0, sizeof opt);
	opt.payout_script = payout;
	opt.payout_script_len = sizeof payout;
	opt.prime_id = 1;
	opt.coinbase_tag = "Blockvase";
	opt.min_difficulty = 65536;
	opt.abw_disabled = true;
	prime_new_resume_token(opt.prime_id, token);
	if (prime_encode_config_v3(&opt, token, &cfg, &cfg_len) != 0) {
		fprintf(stderr, "selftest: encode v3 config failed\n");
		goto done;
	}
	if (prime_session_encrypt(&session, PRIME_CMD_MINING, cfg, cfg_len, true, &cfg_wire, &cfg_wire_len) != 0) {
		fprintf(stderr, "selftest: encrypt config failed\n");
		goto done;
	}

	{
		unsigned char opened_hs[2048];
		unsigned char pool_sess_box[32];
		unsigned char precomp[crypto_box_BEFORENMBYTES];
		unsigned char recv[PRIME_NONCE_LEN];
		unsigned char sendn[PRIME_NONCE_LEN];
		prime_ratchet client_rx;
		prime_header rh, ch;
		uint32_t cts, stc;

		prime_header_keys_from_nk(nk, &cts, &stc);
		(void)cts;
		prime_ratchet_init(&client_rx, stc);
		prime_ratchet_unmask(&client_rx, resp_wire, &rh);
		if (crypto_box_seal_open(opened_hs, resp_wire + 4, rh.cmd_len, sess.box_pk, sess.box_sk) != 0) {
			goto done;
		}
		memcpy(pool_sess_box, opened_hs + 160, 32);
		if (crypto_box_beforenm(precomp, pool_sess_box, sess.box_sk) != 0) {
			fprintf(stderr, "selftest: client beforenm failed\n");
			goto done;
		}
		prime_derive_nonces(nk, sess.sign_pk, recv, sendn);
		(void)sendn;
		prime_ratchet_unmask(&client_rx, cfg_wire, &ch);
		if (crypto_box_open_easy_afternm(opened_hs, cfg_wire + 4, ch.cmd_len, recv, precomp) != 0) {
			fprintf(stderr, "selftest: client could not decrypt config\n");
			goto done;
		}
		plain_len = ch.cmd_len - crypto_box_MACBYTES;
		if (plain_len < crypto_sign_BYTES) {
			goto done;
		}
		if (crypto_sign_verify_detached(opened_hs + plain_len - crypto_sign_BYTES, opened_hs,
						plain_len - crypto_sign_BYTES, session.session_sign_pk) != 0) {
			fprintf(stderr, "selftest: config signature failed\n");
			goto done;
		}
		plain_len -= crypto_sign_BYTES;
		if (plain_len != cfg_len || memcmp(opened_hs, cfg, cfg_len) != 0) {
			fprintf(stderr, "selftest: decrypted config mismatch\n");
			goto done;
		}
		if (opened_hs[0] != PRIME_MINING_CONFIG || opened_hs[1] != PRIME_CONFIG_V3) {
			fprintf(stderr, "selftest: config prefix bad\n");
			goto done;
		}
	}

	(void)plain;
	rc = 0;
done:
	free(hello_wire);
	free(resp_wire);
	free(cfg);
	free(cfg_wire);
	free(plain);
	return rc;
}

static void revcpy(unsigned char *out, const unsigned char *in, size_t n)
{
	size_t i;
	for (i = 0; i < n; i++) {
		out[i] = in[n - 1 - i];
	}
}

static int test_targets_and_header_vector(void)
{
	struct {
		uint8_t exp;
		const char *want;
	} pots[] = {
		{ 0, "0000000100000000000000000000000000000000000000000000000000000000" },
		{ 16, "0000000000010000000000000000000000000000000000000000000000000000" },
		{ 32, "0000000000000001000000000000000000000000000000000000000000000000" },
	};
	unsigned char t[32];
	unsigned char prev[32], merkle[32], en[16], rhs[32], result[32];
	unsigned char prev_disp[32], merkle_disp[32], en_disp[16], rhs_disp[32];
	size_t i;

	for (i = 0; i < sizeof pots / sizeof pots[0]; i++) {
		prime_target_for_pot(pots[i].exp, t);
		if (expect_hex("target_for_pot", t, 32, pots[i].want) != 0) {
			return -1;
		}
	}

	/* RATUM core/tests/data/block_header_v2.json profile_0_time_offset.
	 * Display hex is reversed into the header fields. */
	if (prime_hex_decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
			     prev_disp, 32) != 0
	    || prime_hex_decode("f0e0d0c0b0a090807060504030201000ffeeddccbbaa99887766554433221100",
				merkle_disp, 32) != 0
	    || prime_hex_decode("00112233445566778899aabbccddeeff", en_disp, 16) != 0
	    || prime_hex_decode("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
				rhs_disp, 32) != 0) {
		fprintf(stderr, "selftest: vector hex decode failed\n");
		return -1;
	}
	revcpy(prev, prev_disp, 32);
	revcpy(merkle, merkle_disp, 32);
	revcpy(en, en_disp, 16);
	revcpy(rhs, rhs_disp, 32);
	if (prime_header_pow_hash(prev, merkle, 536870912u, 2000000000u - 600u, 486604799u,
				  195948557u, 287454020u, 2309737967u, 600u, en, 3, 28,
				  840000, rhs, result) != 0) {
		fprintf(stderr, "selftest: header hash failed\n");
		return -1;
	}
	if (expect_hex("profile0 block_hash", result, 32,
		       "4b495dcf05d70a49785b799b22284fbcd9dd1209237c53c87e4674b15587d704") != 0) {
		return -1;
	}
	{
		unsigned char ser[PRIME_HEADER_V2_SIZE];
		unsigned char z16[16];
		memset(z16, 0, sizeof z16);
		prime_header_v2_serialize(ser, 536870912u, prev, merkle, 2000000000u - 600u,
					  486604799u, 195948557u, 287454020u, 2309737967u, en,
					  600u, 3, 28, 0, z16, 840000, rhs);
		if (expect_hex("profile0 serialized", ser, PRIME_HEADER_V2_SIZE,
			       "000000a01f1e1d1c1b1a191817161514131211100f0e0d0c0b0a0908070605040302010000112233445566778899aabbccddeeff00102030405060708090a0b0c0d0e0f0a8913577ffff001d0df0ad0b44332211efcdab89ffeeddccbbaa998877665544332211005802000003001c000000000000000000000000000000000040d10c008967452301efcdab8967452301efcdab8967452301efcdab8967452301efcdab") != 0) {
			return -1;
		}
	}
	if (prime_bits_to_target(0x1d00ffffu, t) != 0) {
		fprintf(stderr, "selftest: bits_to_target failed\n");
		return -1;
	}
	if (t[3] != 0 || t[4] != 0xff || t[5] != 0xff) {
		fprintf(stderr, "selftest: bits_to_target 0x1d00ffff bytes %02x %02x %02x\n",
			t[3], t[4], t[5]);
		return -1;
	}
	{
		unsigned char cs[9];
		if (prime_encode_compact_size(0, cs) != 1 || cs[0] != 0
		    || prime_encode_compact_size(0xfc, cs) != 1 || cs[0] != 0xfc
		    || prime_encode_compact_size(0xfd, cs) != 3 || cs[0] != 0xfd
		    || cs[1] != 0xfd || cs[2] != 0) {
			fprintf(stderr, "selftest: compact size failed\n");
			return -1;
		}
	}
	{
		unsigned char hdr[PRIME_HEADER_V2_SIZE];
		unsigned char cb[100];
		unsigned char *block = NULL;
		size_t blen = 0;
		memset(hdr, 0xaa, sizeof hdr);
		memset(cb, 0xbb, sizeof cb);
		if (prime_serialize_block(hdr, cb, sizeof cb, NULL, NULL, 0, &block, &blen) != 0
		    || blen != 164 + 1 + 100 || block[164] != 1) {
			fprintf(stderr, "selftest: serialize_block failed\n");
			free(block);
			return -1;
		}
		free(block);
	}
	return 0;
}

static int test_ledger_address_abw(void)
{
	prime_pool *p;
	char idents[4][PRIME_MAX_IDENTITY];
	char many_idents[PRIME_MAX_SPLIT_OUTPUTS][PRIME_MAX_IDENTITY];
	uint64_t amounts[4];
	uint64_t many_amounts[PRIME_MAX_SPLIT_OUTPUTS];
	size_t n;
	unsigned char h1[32], h2[32], script[34], z[16], mask[32], kh[32];
	size_t slen = 0;
	unsigned char hash[32];
	size_t i;
	memset(h1, 1, sizeof h1);
	memset(h2, 2, sizeof h2);
	remove("/tmp/c-datum-prime-selftest-ledger.shares");
	remove("/tmp/c-datum-prime-selftest-ledger.window");
	remove("/tmp/c-datum-prime-selftest-ledger-many.shares");
	remove("/tmp/c-datum-prime-selftest-ledger-many.window");
	p = prime_pool_open("/tmp/c-datum-prime-selftest-ledger", 1000000, 0, 0);
	if (!p) {
		fprintf(stderr, "selftest: ledger open failed\n");
		return -1;
	}
	memset(hash, 3, sizeof hash);
	if (prime_pool_record_share(p, "alice", 75, h1, "") != 0
	    || prime_pool_record_share(p, "bob", 25, h2, "") != 0) {
		fprintf(stderr, "selftest: record share failed\n");
		prime_pool_close(p);
		return -1;
	}
	{
		char sj[2048];
		if (prime_pool_stats_json(p, sj, sizeof sj) != 0
		    || !strstr(sj, "\"hashrate_hs\"")
		    || !strstr(sj, "\"hash_percent\"")
		    || !strstr(sj, "\"kind\":\"datum\"")
		    || !strstr(sj, "\"public_work\"")
		    || prime_pool_hashrate_hs(p) <= 0) {
			fprintf(stderr, "selftest: hashrate stats missing\n");
			prime_pool_close(p);
			return -1;
		}
	}
	{
		char sh[1024], hex[65];
		if (prime_pool_shares_json(p, sh, sizeof sh, NULL, 1) != 0
		    || !strstr(sh, "\"hash\"") || !strstr(sh, "\"has_more\":true")) {
			fprintf(stderr, "selftest: shares json page missing\n");
			prime_pool_close(p);
			return -1;
		}
		prime_hex_encode(h1, 32, hex, sizeof hex);
		if (prime_pool_shares_json(p, sh, sizeof sh, h1, 10) != 0
		    || !strstr(sh, "bob") || strstr(sh, "alice")) {
			fprintf(stderr, "selftest: shares json after-cursor failed\n");
			prime_pool_close(p);
			return -1;
		}
	}
	n = prime_pool_split(p, 1000000, idents, amounts, 4);
	if (n != 2 || amounts[0] + amounts[1] != 1000000
	    || strcmp(idents[0], "alice") != 0 || amounts[0] != 750000) {
		fprintf(stderr, "selftest: split got n=%zu a0=%llu\n", n,
			(unsigned long long)(n ? amounts[0] : 0));
		prime_pool_close(p);
		return -1;
	}
	if (!prime_pool_replay_new(p, h1) || prime_pool_replay_new(p, h1)) {
		fprintf(stderr, "selftest: replay guard failed\n");
		prime_pool_close(p);
		return -1;
	}
	prime_pool_close(p);
	p = prime_pool_open("/tmp/c-datum-prime-selftest-ledger-many", 1000000, 0, 0);
	if (!p) {
		fprintf(stderr, "selftest: many ledger open failed\n");
		return -1;
	}
	for (i = 0; i < 12; i++) {
		unsigned char h[32];
		char ident[32];
		memset(h, (int)i + 10, sizeof h);
		snprintf(ident, sizeof ident, "user%02zu", i);
		if (prime_pool_record_share(p, ident, 10, h, "") != 0) {
			fprintf(stderr, "selftest: many record share failed\n");
			prime_pool_close(p);
			return -1;
		}
	}
	n = prime_pool_split(p, 12000, many_idents, many_amounts, 12);
	if (n != 12) {
		fprintf(stderr, "selftest: split cap got n=%zu\n", n);
		prime_pool_close(p);
		return -1;
	}
	prime_pool_close(p);
	if (prime_address_script("bc1q2j96gyue646j840pf4gg9wvgt8gemlyelvxvec", script, &slen,
				 sizeof script) != 0
	    || slen != 22 || script[0] != 0x00 || script[1] != 0x14) {
		fprintf(stderr, "selftest: bech32 p2wpkh failed\n");
		return -1;
	}
	if (prime_address_script("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", script, &slen,
				 sizeof script) != 0
	    || slen != 25 || script[0] != 0x76 || script[1] != 0xa9 || script[2] != 0x14
	    || script[23] != 0x88 || script[24] != 0xac) {
		fprintf(stderr, "selftest: base58 p2pkh failed\n");
		return -1;
	}
	if (prime_address_script("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", script, &slen,
				 sizeof script) != 0
	    || slen != 23 || script[0] != 0xa9 || script[1] != 0x14 || script[22] != 0x87) {
		fprintf(stderr, "selftest: base58 p2sh failed\n");
		return -1;
	}
	memset(z, 0, sizeof z);
	prime_xor_mask(z, 48, mask);
	if (mask[0] || mask[31]) {
		fprintf(stderr, "selftest: zero xor_mask should be zero\n");
		return -1;
	}
	prime_xor_key_hash(z, kh);
	if (prime_window_for_difficulty(1000.0, 8.0, 1) != 8000
	    || prime_window_for_difficulty(0.0, 8.0, 5) != 5
	    || prime_window_for_difficulty(1000.0, 8.0, 100000) != 100000) {
		fprintf(stderr, "selftest: window_for_difficulty failed\n");
		return -1;
	}
	return 0;
}

static int test_require_split(void)
{
	prime_conn_mining st;
	unsigned char paid[] = { 0x00, 0xaa, 0xbb, 0xcc, 0x00 };
	unsigned char pool_only[] = { 0x00, 0x11, 0x22, 0x00 };
	const time_t sent = 1000;
	const time_t late = sent + PRIME_SPLIT_GRACE_SECS + 1;

	prime_conn_mining_init(&st);
	st.job_coinbaser_id = 2;
	st.nsplits = 2;
	/* Decoy: stratum class 4. Keying off that would treat pool_only as paid. */
	st.splits[0].id = 4;
	st.splits[0].sent_at = sent;
	st.splits[0].n = 1;
	st.splits[0].script_lens[0] = 2;
	memcpy(st.splits[0].scripts[0], "\x11\x22", 2);
	st.splits[1].id = 2;
	st.splits[1].sent_at = sent;
	st.splits[1].n = 1;
	st.splits[1].script_lens[0] = 3;
	memcpy(st.splits[1].scripts[0], "\xaa\xbb\xcc", 3);

	if (!prime_require_split_rejected(&st, 0, 0, pool_only, sizeof pool_only, late)) {
		fprintf(stderr, "selftest: require_split should refuse unpaid past grace\n");
		prime_conn_mining_free(&st);
		return -1;
	}
	if (prime_require_split_rejected(&st, 0, 0, paid, sizeof paid, late)
	    || prime_require_split_rejected(&st, 0, 0, pool_only, sizeof pool_only, sent)
	    || prime_require_split_rejected(&st, 1, 0, pool_only, sizeof pool_only, late)
	    || prime_require_split_rejected(&st, 0, 1, pool_only, sizeof pool_only, late)) {
		fprintf(stderr, "selftest: require_split exemptions failed\n");
		prime_conn_mining_free(&st);
		return -1;
	}
	st.job_coinbaser_id = 0;
	if (prime_require_split_rejected(&st, 0, 0, pool_only, sizeof pool_only, late)) {
		fprintf(stderr, "selftest: require_split id 0 should pass\n");
		prime_conn_mining_free(&st);
		return -1;
	}
	st.job_coinbaser_id = 5;
	if (prime_require_split_rejected(&st, 0, 0, pool_only, sizeof pool_only, late)) {
		fprintf(stderr, "selftest: require_split unknown id should pass\n");
		prime_conn_mining_free(&st);
		return -1;
	}
	prime_conn_mining_free(&st);
	return 0;
}

/* Jason's 0x11 rule on the gateway view (payload after the 0x11 byte). */
static int convoy_trailer_has_prevhash(const unsigned char *msg, size_t msg_len,
				       unsigned char prevhash[32])
{
	const unsigned char *data;
	size_t len;
	uint32_t x;

	if (!msg || msg_len < 1 || msg[0] != PRIME_MINING_COINBASER_RESP) {
		return 0;
	}
	data = msg + 1;
	len = msg_len - 1;
	if (len < 12) {
		return 0;
	}
	x = (uint32_t)data[8] | ((uint32_t)data[9] << 8) | ((uint32_t)data[10] << 16)
	    | ((uint32_t)data[11] << 24);
	if (x < 1 || x > len - 12) {
		return 0;
	}
	if (len < 12u + x + PRIME_COINBASER_PREVHASH_TRAILER_LEN
	    || memcmp(data + 12 + x, PRIME_COINBASER_PREVHASH_MAGIC,
		      PRIME_COINBASER_PREVHASH_MAGIC_LEN) != 0) {
		return 0;
	}
	if (prevhash) {
		memcpy(prevhash, data + 12 + x + PRIME_COINBASER_PREVHASH_MAGIC_LEN, 32);
	}
	return 1;
}

static int expect_trailer(const char *what, const unsigned char *msg, size_t msg_len,
			  int want_has, const unsigned char *want_prev)
{
	unsigned char got[32];
	int has = convoy_trailer_has_prevhash(msg, msg_len, got);

	if (has != want_has) {
		fprintf(stderr, "selftest: %s has_prevhash=%d want %d\n", what, has, want_has);
		return -1;
	}
	if (want_has && want_prev && memcmp(got, want_prev, 32) != 0) {
		fprintf(stderr, "selftest: %s prevhash mismatch\n", what);
		return -1;
	}
	return 0;
}

static int test_coinbaser_prevhash(void)
{
	unsigned char script[22] = {0x00, 0x14};
	unsigned char parent[32], other[32];
	unsigned char *out = NULL;
	size_t out_len = 0;
	uint32_t blob_len;
	unsigned char pad[256];
	size_t i;

	memset(parent, 0x5e, sizeof parent);
	memset(other, 0xa1, sizeof other);
	if (PRIME_COINBASER_PREVHASH_MAGIC[0] == PRIME_COINBASER_PREVHASH_MAGIC[1]
	    && PRIME_COINBASER_PREVHASH_MAGIC[1] == PRIME_COINBASER_PREVHASH_MAGIC[2]
	    && PRIME_COINBASER_PREVHASH_MAGIC[2] == PRIME_COINBASER_PREVHASH_MAGIC[3]) {
		fprintf(stderr, "selftest: magic bytes are all equal\n");
		return -1;
	}
	if (prime_encode_coinbaser_response(5000000000ULL, 3, script, sizeof script, NULL, &out,
					    &out_len) != 0) {
		fprintf(stderr, "selftest: stock coinbaser encode failed\n");
		return -1;
	}
	if (out_len != 1 + 8 + 4 + 1 + 8 + 1 + 22) {
		fprintf(stderr, "selftest: stock coinbaser len %zu\n", out_len);
		free(out);
		return -1;
	}
	/* Stock CONVOY / OCEAN: value + blob only. */
	if (expect_trailer("stock", out, out_len, 0, NULL) != 0) {
		free(out);
		return -1;
	}
	/* CONVOY if it pads like the gateway (one byte repeated). */
	{
		const size_t pads[] = { 31, 32, 100 };
		for (i = 0; i < sizeof pads / sizeof pads[0]; i++) {
			memcpy(pad, out, out_len);
			memset(pad + out_len, 0x7a, pads[i]);
			if (expect_trailer("pad", pad, out_len + pads[i], 0, NULL) != 0) {
				free(out);
				return -1;
			}
		}
	}
	free(out);
	if (prime_encode_coinbaser_response(5000000000ULL, 3, script, sizeof script, parent, &out,
					    &out_len) != 0) {
		fprintf(stderr, "selftest: prevhash coinbaser encode failed\n");
		return -1;
	}
	if (out_len != 1 + 8 + 4 + 1 + 8 + 1 + 22 + PRIME_COINBASER_PREVHASH_TRAILER_LEN) {
		fprintf(stderr, "selftest: prevhash coinbaser len %zu\n", out_len);
		free(out);
		return -1;
	}
	blob_len = (uint32_t)out[9] | ((uint32_t)out[10] << 8) | ((uint32_t)out[11] << 16)
		   | ((uint32_t)out[12] << 24);
	if (blob_len != 1 + 8 + 1 + 22) {
		fprintf(stderr, "selftest: blob_len includes trailer (%u)\n", blob_len);
		free(out);
		return -1;
	}
	if (memcmp(out + out_len - PRIME_COINBASER_PREVHASH_TRAILER_LEN,
		   PRIME_COINBASER_PREVHASH_MAGIC, PRIME_COINBASER_PREVHASH_MAGIC_LEN) != 0
	    || memcmp(out + out_len - 32, parent, 32) != 0) {
		fprintf(stderr, "selftest: prevhash trailer mismatch\n");
		free(out);
		return -1;
	}
	/* Proposed CONVOY / this Prime: magic + request parent. */
	if (expect_trailer("magic+parent", out, out_len, 1, parent) != 0) {
		free(out);
		return -1;
	}
	memcpy(out + out_len - 32, other, 32);
	if (expect_trailer("magic+other", out, out_len, 1, other) != 0) {
		free(out);
		return -1;
	}
	memcpy(out + out_len - PRIME_COINBASER_PREVHASH_TRAILER_LEN, "XXXX", 4);
	memcpy(out + out_len - 32, parent, 32);
	if (expect_trailer("wrong magic", out, out_len, 0, NULL) != 0) {
		free(out);
		return -1;
	}
	free(out);
	return 0;
}

static int test_fee_after_first_block(void)
{
	prime_pool *p;
	char idents[4][PRIME_MAX_IDENTITY];
	uint64_t amounts[4];
	unsigned char hash[32];
	size_t n;
	const char *path = "/tmp/c-datum-prime-selftest-fee-after";

	remove("/tmp/c-datum-prime-selftest-fee-after.shares");
	remove("/tmp/c-datum-prime-selftest-fee-after.window");
	remove("/tmp/c-datum-prime-selftest-fee-after.blocks");
	remove("/tmp/c-datum-prime-selftest-fee-after.owed");
	p = prime_pool_open(path, 1000000, 0, 0);
	if (!p) {
		fprintf(stderr, "selftest: fee-after open failed\n");
		return -1;
	}
	prime_pool_set_fee_after_first_block(p, 21);
	if (prime_pool_fee_bps(p) != 0 || prime_pool_blocks_found(p) != 0) {
		fprintf(stderr, "selftest: fee-after should start at 0 bps\n");
		prime_pool_close(p);
		return -1;
	}
	memset(hash, 9, sizeof hash);
	if (prime_pool_record_share(p, "alice", 100, hash, "") != 0) {
		fprintf(stderr, "selftest: fee-after record share failed\n");
		prime_pool_close(p);
		return -1;
	}
	n = prime_pool_split(p, 1000000, idents, amounts, 4);
	if (n != 1 || amounts[0] != 1000000) {
		fprintf(stderr, "selftest: fee-after pre-block split n=%zu a0=%llu\n", n,
			(unsigned long long)(n ? amounts[0] : 0));
		prime_pool_close(p);
		return -1;
	}
	if (prime_pool_record_block(p, 1, hash, "alice", 1000000, 0) != 0
	    || prime_pool_fee_bps(p) != 21 || prime_pool_blocks_found(p) != 1) {
		fprintf(stderr, "selftest: fee-after first block did not flip to 21 bps\n");
		prime_pool_close(p);
		return -1;
	}
	n = prime_pool_split(p, 1000000, idents, amounts, 4);
	if (n != 1 || amounts[0] != 997900) {
		fprintf(stderr, "selftest: fee-after post-block split n=%zu a0=%llu\n", n,
			(unsigned long long)(n ? amounts[0] : 0));
		prime_pool_close(p);
		return -1;
	}
	prime_pool_close(p);
	p = prime_pool_open(path, 1000000, 0, 0);
	if (!p) {
		fprintf(stderr, "selftest: fee-after reopen failed\n");
		return -1;
	}
	prime_pool_set_fee_after_first_block(p, 21);
	if (prime_pool_fee_bps(p) != 21 || prime_pool_blocks_found(p) != 1) {
		fprintf(stderr, "selftest: fee-after reopen lost block/fee (fee=%u blocks=%llu)\n",
			(unsigned)prime_pool_fee_bps(p),
			(unsigned long long)prime_pool_blocks_found(p));
		prime_pool_close(p);
		return -1;
	}
	prime_pool_close(p);
	return 0;
}

static int test_sv1_rebate_split(void)
{
	prime_pool *p;
	char idents[4][PRIME_MAX_IDENTITY];
	uint64_t amounts[4];
	unsigned char h1[32], h2[32];
	size_t n;
	uint64_t alice = 0, bob = 0, i;
	const char *path = "/tmp/c-datum-prime-selftest-sv1";

	remove("/tmp/c-datum-prime-selftest-sv1.shares");
	remove("/tmp/c-datum-prime-selftest-sv1.window");
	p = prime_pool_open(path, 1000000, 0, 0);
	if (!p) {
		fprintf(stderr, "selftest: sv1 open failed\n");
		return -1;
	}
	memset(h1, 1, sizeof h1);
	memset(h2, 2, sizeof h2);
	if (prime_pool_record_share(p, "alice", 75, h1, "") != 0
	    || prime_pool_record_share(p, "bob", 25, h2, PRIME_SV1_TAG) != 0) {
		fprintf(stderr, "selftest: sv1 record failed\n");
		prime_pool_close(p);
		return -1;
	}
	n = prime_pool_split(p, 1000000, idents, amounts, 4);
	for (i = 0; i < n; i++) {
		if (!strcmp(idents[i], "alice")) {
			alice = amounts[i];
		}
		if (!strcmp(idents[i], "bob")) {
			bob = amounts[i];
		}
	}
	/* public slice 250000: bob keeps 97.7% = 244250; 2% = 5000 to alice; 0.3% leftover */
	if (n != 2 || alice != 755000 || bob != 244250) {
		fprintf(stderr, "selftest: sv1 pre-block split n=%zu alice=%llu bob=%llu\n", n,
			(unsigned long long)alice, (unsigned long long)bob);
		prime_pool_close(p);
		return -1;
	}
	prime_pool_set_fee_after_first_block(p, 21);
	if (prime_pool_record_block(p, 1, h1, "alice", 997900, 2100) != 0) {
		fprintf(stderr, "selftest: sv1 record block failed\n");
		prime_pool_close(p);
		return -1;
	}
	alice = bob = 0;
	n = prime_pool_split(p, 1000000, idents, amounts, 4);
	for (i = 0; i < n; i++) {
		if (!strcmp(idents[i], "alice")) {
			alice = amounts[i];
		}
		if (!strcmp(idents[i], "bob")) {
			bob = amounts[i];
		}
	}
	/* datum slice 750000 minus 21 bps (1575) plus rebate 5000 = 753425 */
	if (n != 2 || alice != 753425 || bob != 244250) {
		fprintf(stderr, "selftest: sv1 post-block split n=%zu alice=%llu bob=%llu\n", n,
			(unsigned long long)alice, (unsigned long long)bob);
		prime_pool_close(p);
		return -1;
	}
	prime_pool_close(p);
	return 0;
}

static int test_window_holds_until_difficulty(void)
{
	prime_pool *p;
	const char *path = "/tmp/c-datum-prime-selftest-window-hold";
	unsigned char h[32];
	size_t i;

	remove("/tmp/c-datum-prime-selftest-window-hold.shares");
	remove("/tmp/c-datum-prime-selftest-window-hold.window");
	p = prime_pool_open(path, 1000000000ull, 0, 0);
	if (!p) {
		fprintf(stderr, "selftest: window-hold open failed\n");
		return -1;
	}
	for (i = 0; i < 10; i++) {
		memset(h, (int)i + 1, sizeof h);
		if (prime_pool_record_share(p, "alice", 65536, h, "") != 0) {
			fprintf(stderr, "selftest: window-hold record failed\n");
			prime_pool_close(p);
			return -1;
		}
	}
	if (prime_pool_share_count(p) != 10 || prime_pool_total_work(p) != 655360) {
		fprintf(stderr, "selftest: window-hold seed count=%llu work=%llu\n",
			(unsigned long long)prime_pool_share_count(p),
			(unsigned long long)prime_pool_total_work(p));
		prime_pool_close(p);
		return -1;
	}
	prime_pool_close(p);

	p = prime_pool_open(path, 0, 0, 0);
	if (!p) {
		fprintf(stderr, "selftest: window-hold reopen pending failed\n");
		return -1;
	}
	if (prime_pool_share_count(p) != 10) {
		fprintf(stderr, "selftest: pending open dropped shares to %llu\n",
			(unsigned long long)prime_pool_share_count(p));
		prime_pool_close(p);
		return -1;
	}
	memset(h, 99, sizeof h);
	if (prime_pool_record_share(p, "bob", 65536, h, "") != 0
	    || prime_pool_share_count(p) != 11) {
		fprintf(stderr, "selftest: pending share trimmed window to %llu\n",
			(unsigned long long)prime_pool_share_count(p));
		prime_pool_close(p);
		return -1;
	}
	prime_pool_set_window(p, 1000000000ull);
	if (prime_pool_share_count(p) != 11) {
		fprintf(stderr, "selftest: set_window dropped shares to %llu\n",
			(unsigned long long)prime_pool_share_count(p));
		prime_pool_close(p);
		return -1;
	}
	prime_pool_close(p);

	p = prime_pool_open(path, 0, 0, 0);
	if (!p || prime_pool_share_count(p) != 11
	    || prime_pool_window(p) != 1000000000ull) {
		fprintf(stderr, "selftest: saved window reopen count=%llu window=%llu\n",
			(unsigned long long)(p ? prime_pool_share_count(p) : 0),
			(unsigned long long)(p ? prime_pool_window(p) : 0));
		if (p) {
			prime_pool_close(p);
		}
		return -1;
	}
	prime_pool_close(p);
	return 0;
}

static int test_nethash_cap(void)
{
	prime_pool *p;
	unsigned char h[32];
	uint64_t total = 0, sv1 = 0, oldest = 0, count = 0;
	int admit = 1, kick_all = 0, shed = 0;
	const char *path = "/tmp/c-datum-prime-selftest-nethash";

	remove("/tmp/c-datum-prime-selftest-nethash.shares");
	remove("/tmp/c-datum-prime-selftest-nethash.window");
	p = prime_pool_open(path, 1000000, 0, 0);
	if (!p) {
		fprintf(stderr, "selftest: nethash open failed\n");
		return -1;
	}
	memset(h, 9, sizeof h);
	if (prime_pool_record_share(p, "alice", 100, h, "") != 0
	    || prime_pool_record_share(p, "bob", 50, h, PRIME_SV1_TAG) != 0) {
		fprintf(stderr, "selftest: nethash record failed\n");
		prime_pool_close(p);
		return -1;
	}
	if (prime_pool_work_since(p, 0, &total, &sv1, &oldest, &count) != 0
	    || total != 150 || sv1 != 50 || count != 2 || !oldest) {
		fprintf(stderr, "selftest: work_since total=%llu sv1=%llu count=%llu\n",
			(unsigned long long)total, (unsigned long long)sv1,
			(unsigned long long)count);
		prime_pool_close(p);
		return -1;
	}
	if (prime_pool_work_since(p, (uint64_t)time(NULL) + 60, &total, &sv1, &oldest, &count) != 0
	    || total || sv1 || count) {
		fprintf(stderr, "selftest: work_since future cutoff leaked work\n");
		prime_pool_close(p);
		return -1;
	}
	if (prime_work_to_hashrate_hs(1, 1) != PRIME_HASHES_PER_DIFF) {
		fprintf(stderr, "selftest: work_to_hashrate_hs failed\n");
		prime_pool_close(p);
		return -1;
	}
	prime_cap_policy(0.10, 0.10, 1, &admit, &kick_all, &shed);
	if (!admit || kick_all || shed) {
		fprintf(stderr, "selftest: cap under 25%% should stay open\n");
		prime_pool_close(p);
		return -1;
	}
	prime_cap_policy(0.26, 0.10, 1, &admit, &kick_all, &shed);
	if (admit || kick_all || !shed) {
		fprintf(stderr, "selftest: cap over 25%% should close and shed SV1\n");
		prime_pool_close(p);
		return -1;
	}
	prime_cap_policy(0.26, 0.26, 1, &admit, &kick_all, &shed);
	if (admit || !kick_all || !shed) {
		fprintf(stderr, "selftest: DATUM-only over cap should kick all SV1\n");
		prime_pool_close(p);
		return -1;
	}
	prime_cap_policy(0.24, 0.10, 0, &admit, &kick_all, &shed);
	if (admit || kick_all || !shed) {
		fprintf(stderr, "selftest: closed above kick-to should keep shedding\n");
		prime_pool_close(p);
		return -1;
	}
	prime_cap_policy(0.225, 0.10, 0, &admit, &kick_all, &shed);
	if (admit || kick_all || shed) {
		fprintf(stderr, "selftest: hysteresis band should stay closed without shed\n");
		prime_pool_close(p);
		return -1;
	}
	prime_cap_policy(0.21, 0.10, 0, &admit, &kick_all, &shed);
	if (!admit || kick_all || shed) {
		fprintf(stderr, "selftest: under resume should reopen\n");
		prime_pool_close(p);
		return -1;
	}
	prime_pool_close(p);
	return 0;
}

static int test_empty_find_snapshot(void)
{
	prime_pool *p;
	const char *path = "/tmp/c-datum-prime-selftest-empty";
	const char *fee_path = "/tmp/c-datum-prime-selftest-empty-fee";
	unsigned char hash[32];
	char idents[4][PRIME_MAX_IDENTITY];
	uint64_t amounts[4];
	size_t n;
	FILE *cap;
	char buf[4096];

	remove("/tmp/c-datum-prime-selftest-empty.shares");
	remove("/tmp/c-datum-prime-selftest-empty.window");
	remove("/tmp/c-datum-prime-selftest-empty.blocks");
	remove("/tmp/c-datum-prime-selftest-empty.owed");
	remove("/tmp/c-datum-prime-selftest-empty.empty");
	p = prime_pool_open(path, 1000000, 546, 0);
	if (!p) {
		fprintf(stderr, "selftest: empty snapshot open failed\n");
		return -1;
	}
	memset(hash, 1, sizeof hash);
	if (prime_pool_record_share(p, "bc1qaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 65536, hash,
				    "") != 0) {
		fprintf(stderr, "selftest: empty snapshot alice share failed\n");
		prime_pool_close(p);
		return -1;
	}
	memset(hash, 2, sizeof hash);
	if (prime_pool_record_share(p, "bc1qbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 65536, hash,
				    "") != 0) {
		fprintf(stderr, "selftest: empty snapshot bob share failed\n");
		prime_pool_close(p);
		return -1;
	}
	memset(hash, 9, sizeof hash);
	if (prime_pool_record_empty(p, 100, hash, "bc1qaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				    100000000) != 0
	    || prime_pool_empty_count(p) != 1
	    || prime_pool_empty_unsettled(p) != 1) {
		fprintf(stderr, "selftest: empty snapshot record failed\n");
		prime_pool_close(p);
		return -1;
	}
	prime_pool_close(p);
	p = prime_pool_open(path, 1000000, 546, 0);
	if (!p || prime_pool_empty_count(p) != 1 || prime_pool_empty_unsettled(p) != 1) {
		fprintf(stderr, "selftest: empty snapshot did not reload\n");
		if (p) {
			prime_pool_close(p);
		}
		return -1;
	}
	{
		char ej[4096];
		if (prime_pool_empty_json(p, ej, sizeof ej) != 0
		    || !strstr(ej, "\"empty_finds\":1")
		    || !strstr(ej, "\"empty_unsettled\":1")
		    || !strstr(ej, "\"settled\":false")
		    || !strstr(ej, "bc1qaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
		    || !strstr(ej, "\"payouts\"")
		    || !strstr(ej, "\"leftover_sats\"")) {
			fprintf(stderr, "selftest: empty json missing snapshot\n");
			prime_pool_close(p);
			return -1;
		}
	}
	n = prime_pool_split(p, 100000000, idents, amounts, 4);
	if (n < 2) {
		fprintf(stderr, "selftest: empty snapshot split n=%zu\n", n);
		prime_pool_close(p);
		return -1;
	}
	cap = fopen("/tmp/c-datum-prime-selftest-empty.out", "w+");
	if (!cap || prime_pool_empty_sendmany(p, hash, cap) != 0) {
		fprintf(stderr, "selftest: empty sendmany failed\n");
		if (cap) {
			fclose(cap);
		}
		prime_pool_close(p);
		return -1;
	}
	rewind(cap);
	if (!fread(buf, 1, sizeof buf - 1, cap)) {
		buf[0] = 0;
	} else {
		buf[sizeof buf - 1] = 0;
	}
	fclose(cap);
	if (!strstr(buf, "bc1qaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	    || !strstr(buf, "bc1qbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	    || !strstr(buf, "sendmany")
	    || !strstr(buf, "0.50000000")) {
		fprintf(stderr, "selftest: empty sendmany missing alice/bob split\n");
		prime_pool_close(p);
		return -1;
	}
	if (prime_pool_settle_empty(p, hash, 123) != 0 || prime_pool_empty_unsettled(p) != 0) {
		fprintf(stderr, "selftest: empty settle failed\n");
		prime_pool_close(p);
		return -1;
	}
	if (prime_pool_void_empty(p, hash) != 0 || prime_pool_empty_count(p) != 0) {
		fprintf(stderr, "selftest: empty void failed\n");
		prime_pool_close(p);
		return -1;
	}
	memset(hash, 4, sizeof hash);
	if (prime_pool_prepare_empty(p, 101, hash, "bc1qaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				     100000000) != 0
	    || prime_pool_empty_count(p) != 0) {
		fprintf(stderr, "selftest: empty prepare should stay pending\n");
		prime_pool_close(p);
		return -1;
	}
	prime_pool_close(p);
	p = prime_pool_open(path, 1000000, 546, 0);
	if (!p || prime_pool_empty_count(p) != 0) {
		fprintf(stderr, "selftest: empty prepare leaked to disk\n");
		if (p) {
			prime_pool_close(p);
		}
		return -1;
	}
	if (prime_pool_prepare_empty(p, 101, hash, "bc1qaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				     100000000) != 0
	    || prime_pool_commit_empty(p, hash) != 0
	    || prime_pool_empty_count(p) != 1) {
		fprintf(stderr, "selftest: empty commit failed\n");
		prime_pool_close(p);
		return -1;
	}
	memset(hash, 5, sizeof hash);
	if (prime_pool_prepare_empty(p, 102, hash, "bc1qaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				     100000000) != 0
	    || prime_pool_abort_empty(p, hash) != 0
	    || prime_pool_empty_count(p) != 1) {
		fprintf(stderr, "selftest: empty abort failed\n");
		prime_pool_close(p);
		return -1;
	}
	prime_pool_close(p);
	p = prime_pool_open(path, 1000000, 546, 0);
	if (!p || prime_pool_empty_count(p) != 1) {
		fprintf(stderr, "selftest: empty commit did not persist\n");
		if (p) {
			prime_pool_close(p);
		}
		return -1;
	}
	prime_pool_close(p);
	remove("/tmp/c-datum-prime-selftest-empty.shares");
	remove("/tmp/c-datum-prime-selftest-empty.window");
	remove("/tmp/c-datum-prime-selftest-empty.blocks");
	remove("/tmp/c-datum-prime-selftest-empty.owed");
	remove("/tmp/c-datum-prime-selftest-empty.empty");
	remove("/tmp/c-datum-prime-selftest-empty.out");

	remove("/tmp/c-datum-prime-selftest-empty-fee.shares");
	remove("/tmp/c-datum-prime-selftest-empty-fee.window");
	remove("/tmp/c-datum-prime-selftest-empty-fee.blocks");
	remove("/tmp/c-datum-prime-selftest-empty-fee.owed");
	remove("/tmp/c-datum-prime-selftest-empty-fee.empty");
	p = prime_pool_open(fee_path, 1000000, 546, 21);
	if (!p) {
		fprintf(stderr, "selftest: empty fee open failed\n");
		return -1;
	}
	memset(hash, 1, sizeof hash);
	if (prime_pool_record_share(p, "bc1qaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 65536, hash,
				    "") != 0) {
		fprintf(stderr, "selftest: empty fee alice share failed\n");
		prime_pool_close(p);
		return -1;
	}
	memset(hash, 2, sizeof hash);
	if (prime_pool_record_share(p, "bc1qbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 65536, hash,
				    PRIME_SV1_TAG) != 0) {
		fprintf(stderr, "selftest: empty fee bob share failed\n");
		prime_pool_close(p);
		return -1;
	}
	memset(hash, 9, sizeof hash);
	n = prime_pool_split(p, 100000000, idents, amounts, 4);
	if (prime_pool_record_empty(p, 100, hash, "bc1qaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				    100000000) != 0) {
		fprintf(stderr, "selftest: empty fee record failed\n");
		prime_pool_close(p);
		return -1;
	}
	prime_pool_close(p);
	p = prime_pool_open(fee_path, 1000000, 546, 0);
	if (!p) {
		fprintf(stderr, "selftest: empty fee reload failed\n");
		return -1;
	}
	cap = fopen("/tmp/c-datum-prime-selftest-empty-fee.out", "w+");
	if (!cap || prime_pool_empty_sendmany(p, hash, cap) != 0) {
		fprintf(stderr, "selftest: empty fee sendmany failed\n");
		if (cap) {
			fclose(cap);
		}
		prime_pool_close(p);
		return -1;
	}
	rewind(cap);
	if (!fread(buf, 1, sizeof buf - 1, cap)) {
		buf[0] = 0;
	} else {
		buf[sizeof buf - 1] = 0;
	}
	fclose(cap);
	{
		char want_a[32], want_b[32];
		uint64_t alice = 0, bob = 0;
		size_t i;
		for (i = 0; i < n; i++) {
			if (strstr(idents[i], "aaaa")) {
				alice = amounts[i];
			}
			if (strstr(idents[i], "bbbb")) {
				bob = amounts[i];
			}
		}
		snprintf(want_a, sizeof want_a, "%llu.%08llu",
			 (unsigned long long)(alice / 100000000ull),
			 (unsigned long long)(alice % 100000000ull));
		snprintf(want_b, sizeof want_b, "%llu.%08llu",
			 (unsigned long long)(bob / 100000000ull),
			 (unsigned long long)(bob % 100000000ull));
		if (!alice || !bob || !strstr(buf, want_a) || !strstr(buf, want_b)
		    || strstr(buf, "0.50000000")) {
			fprintf(stderr, "selftest: empty fee sendmany ignored split %s %s\n",
				want_a, want_b);
			prime_pool_close(p);
			return -1;
		}
	}
	prime_pool_close(p);
	remove("/tmp/c-datum-prime-selftest-empty-full.shares");
	remove("/tmp/c-datum-prime-selftest-empty-full.window");
	remove("/tmp/c-datum-prime-selftest-empty-full.blocks");
	remove("/tmp/c-datum-prime-selftest-empty-full.owed");
	remove("/tmp/c-datum-prime-selftest-empty-full.empty");
	p = prime_pool_open("/tmp/c-datum-prime-selftest-empty-full", 1000000, 546, 0);
	if (!p) {
		fprintf(stderr, "selftest: empty full open failed\n");
		return -1;
	}
	memset(hash, 1, sizeof hash);
	if (prime_pool_record_share(p, "bc1qaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 65536, hash,
				    "") != 0) {
		fprintf(stderr, "selftest: empty full share failed\n");
		prime_pool_close(p);
		return -1;
	}
	{
		unsigned char first[32];
		unsigned char extra[32];
		size_t i;
		memset(first, 0, sizeof first);
		first[0] = 1;
		for (i = 0; i < 32; i++) {
			unsigned char h[32];
			memset(h, 0, sizeof h);
			h[0] = (unsigned char)(i + 1);
			if (prime_pool_record_empty(p, (uint32_t)(200 + i), h,
						    "bc1qaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
						    100000000) != 0) {
				fprintf(stderr, "selftest: empty full record %zu failed\n", i);
				prime_pool_close(p);
				return -1;
			}
		}
		if (prime_pool_empty_count(p) != 32) {
			fprintf(stderr, "selftest: empty full count %zu\n",
				prime_pool_empty_count(p));
			prime_pool_close(p);
			return -1;
		}
		memset(extra, 0xaa, sizeof extra);
		cap = fopen("/dev/null", "w");
		if (!cap
		    || prime_pool_prepare_empty(p, 300, extra,
						"bc1qaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
						100000000) == 0
		    || prime_pool_empty_count(p) != 32
		    || prime_pool_empty_sendmany(p, first, cap) != 0) {
			fprintf(stderr, "selftest: empty prepare evicted an unsettled find\n");
			if (cap) {
				fclose(cap);
			}
			prime_pool_close(p);
			return -1;
		}
		fclose(cap);
	}
	prime_pool_close(p);
	remove("/tmp/c-datum-prime-selftest-empty-full.shares");
	remove("/tmp/c-datum-prime-selftest-empty-full.window");
	remove("/tmp/c-datum-prime-selftest-empty-full.blocks");
	remove("/tmp/c-datum-prime-selftest-empty-full.owed");
	remove("/tmp/c-datum-prime-selftest-empty-full.empty");
	remove("/tmp/c-datum-prime-selftest-empty-fee.shares");
	remove("/tmp/c-datum-prime-selftest-empty-fee.window");
	remove("/tmp/c-datum-prime-selftest-empty-fee.blocks");
	remove("/tmp/c-datum-prime-selftest-empty-fee.owed");
	remove("/tmp/c-datum-prime-selftest-empty-fee.empty");
	remove("/tmp/c-datum-prime-selftest-empty-fee.out");
	return 0;
}

int prime_selftest(void)
{
	if (sodium_init() < 0) {
		fprintf(stderr, "selftest: sodium_init failed\n");
		return 1;
	}
	if (test_feedback() != 0
	    || test_headers() != 0
	    || test_nk_and_nonces() != 0
	    || test_handshake_and_config() != 0
	    || test_targets_and_header_vector() != 0
	    || test_ledger_address_abw() != 0
	    || test_require_split() != 0
	    || test_coinbaser_prevhash() != 0
	    || test_fee_after_first_block() != 0
	    || test_sv1_rebate_split() != 0
	    || test_window_holds_until_difficulty() != 0
	    || test_nethash_cap() != 0
	    || test_empty_find_snapshot() != 0) {
		fprintf(stderr, "selftest: FAILED\n");
		return 1;
	}
	printf("selftest: ok (framing + handshake + RATUM header/target vectors)\n");
	return 0;
}
