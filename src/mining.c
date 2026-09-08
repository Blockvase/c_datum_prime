/* Translated from RATUM core/src/datum/messages.rs, share.rs and prime/src/connection.rs
 * by iohzrd.
 * Copyright (C) iohzrd and RATUM contributors
 * Copyright (C) Blockvase contributors (C translation)
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#include "prime.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define SECTION_JOB 0x01
#define SECTION_COINBASE 0x02
#define SECTION_BLAKE2B 0x03
#define SECTION_ABW_SLOT 0x05
#define BLAKE2B_ALGORITHM 0x01
#define BLAKE2B_TIME 0x04
#define REJECT_BAD_JOB 10
#define REJECT_BAD_EN 12
#define REJECT_HIGH_HASH 21
#define REJECT_OTHER 30
#define REJECT_BLAKE 40

static uint16_t rd_u16(const unsigned char *p)
{
	return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t rd_u32(const unsigned char *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t rd_u64(const unsigned char *p)
{
	uint64_t v = 0;
	int i;
	for (i = 0; i < 8; i++) {
		v |= (uint64_t)p[i] << (8 * i);
	}
	return v;
}

static void wr_u16(unsigned char *p, uint16_t v)
{
	p[0] = (unsigned char)v;
	p[1] = (unsigned char)(v >> 8);
}

static void wr_u32(unsigned char *p, uint32_t v)
{
	p[0] = (unsigned char)v;
	p[1] = (unsigned char)(v >> 8);
	p[2] = (unsigned char)(v >> 16);
	p[3] = (unsigned char)(v >> 24);
}

static const unsigned char *find_bytes(const unsigned char *h, size_t hn,
				       const unsigned char *n, size_t nn)
{
	size_t i;
	if (!n || !nn || hn < nn) {
		return NULL;
	}
	for (i = 0; i + nn <= hn; i++) {
		if (memcmp(h + i, n, nn) == 0) {
			return h + i;
		}
	}
	return NULL;
}

static void wr_u64(unsigned char *p, uint64_t v)
{
	int i;
	for (i = 0; i < 8; i++) {
		p[i] = (unsigned char)(v >> (8 * i));
	}
}

void prime_conn_mining_init(prime_conn_mining *m)
{
	memset(m, 0, sizeof *m);
	m->next_coinbaser_id = 1;
}

static prime_split_rec *split_slot_for(prime_conn_mining *st, uint8_t id)
{
	size_t i, oldest = 0;
	size_t maxn = sizeof st->splits / sizeof st->splits[0];

	for (i = 0; i < st->nsplits; i++) {
		if (st->splits[i].id == id) {
			return &st->splits[i];
		}
		if (st->splits[i].sent_at < st->splits[oldest].sent_at) {
			oldest = i;
		}
	}
	if (st->nsplits < maxn) {
		return &st->splits[st->nsplits++];
	}
	return &st->splits[oldest];
}

/* RATUM check_split: key off the job's datum_coinbaser_id, not the share's
 * stratum class. Class 4 after CONVOY #10 is not a coinbaser id. */
int prime_require_split_rejected(const prime_conn_mining *st, int subsidy_only,
				 int meets_network, const unsigned char *coinbase,
				 size_t coinbase_len, time_t now)
{
	size_t si, oi;
	const prime_split_rec *r = NULL;
	uint8_t id;

	if (subsidy_only || meets_network || !coinbase || !st) {
		return 0;
	}
	id = st->job_coinbaser_id;
	if (id == 0) {
		return 0;
	}
	for (si = 0; si < st->nsplits; si++) {
		if (st->splits[si].id == id) {
			r = &st->splits[si];
			break;
		}
	}
	if (!r || !r->n) {
		return 0;
	}
	if (now < r->sent_at || (uint64_t)(now - r->sent_at) <= PRIME_SPLIT_GRACE_SECS) {
		return 0;
	}
	for (oi = 0; oi < r->n; oi++) {
		if (r->script_lens[oi]
		    && find_bytes(coinbase, coinbase_len, r->scripts[oi], r->script_lens[oi])) {
			return 0;
		}
	}
	return 1;
}

static void clear_pending_block(prime_conn_mining *m)
{
	free(m->pending_coinbase);
	m->pending_coinbase = NULL;
	m->pending_coinbase_len = 0;
	m->have_pending_block = 0;
}

void prime_conn_mining_free(prime_conn_mining *m)
{
	free(m->coinb1);
	free(m->coinb2);
	clear_pending_block(m);
	memset(m, 0, sizeof *m);
}

int prime_submit_block(const prime_config_opts *opt, const unsigned char *block, size_t block_len,
		       const unsigned char hash[32])
{
	char hash_disp[65];
	char path[512];
	unsigned char rev[32];
	char *hex = NULL;
	FILE *f;
	int i;
	int rc = -1;

	for (i = 0; i < 32; i++) {
		rev[i] = hash[31 - i];
	}
	if (prime_hex_encode(rev, 32, hash_disp, sizeof hash_disp) != 0) {
		return -1;
	}
	fprintf(stderr, "prime: BLOCK %s (%zu bytes)\n", hash_disp, block_len);
	if (opt && opt->block_dir && opt->block_dir[0]) {
		if (mkdir(opt->block_dir, 0700) != 0 && errno != EEXIST) {
			fprintf(stderr, "prime: could not create %s: %s\n", opt->block_dir,
				strerror(errno));
		} else {
			int n = snprintf(path, sizeof path, "%s/%s.hex", opt->block_dir, hash_disp);
			if (n > 0 && (size_t)n < sizeof path) {
				hex = malloc(block_len * 2 + 1);
				if (hex && prime_hex_encode(block, block_len, hex, block_len * 2 + 1) == 0) {
					f = fopen(path, "w");
					if (f) {
						fwrite(hex, 1, block_len * 2, f);
						fclose(f);
						fprintf(stderr, "prime: wrote %s\n", path);
						rc = 0;
					}
				}
			}
		}
	}
	if (opt && opt->bitcoin_datadir && opt->bitcoin_datadir[0]) {
		int fds[2];
		pid_t pid;
		if (pipe(fds) != 0) {
			fprintf(stderr, "prime: submitblock pipe failed: %s\n", strerror(errno));
			free(hex);
			return rc;
		}
		pid = fork();
		if (pid < 0) {
			fprintf(stderr, "prime: submitblock fork failed: %s\n", strerror(errno));
			close(fds[0]);
			close(fds[1]);
			free(hex);
			return rc;
		}
		if (pid == 0) {
			char darg[600];
			dup2(fds[0], STDIN_FILENO);
			close(fds[0]);
			close(fds[1]);
			if (prime_rpc_datadir_arg(opt->bitcoin_datadir, darg, sizeof darg) != 0) {
				_exit(127);
			}
			execlp("bitcoin-cli", "bitcoin-cli", darg, "-stdin", "submitblock",
			       (char *)NULL);
			_exit(127);
		}
		close(fds[0]);
		if (!hex) {
			hex = malloc(block_len * 2 + 1);
			if (hex) {
				prime_hex_encode(block, block_len, hex, block_len * 2 + 1);
			}
		}
		if (hex) {
			if (write(fds[1], hex, block_len * 2) != (ssize_t)(block_len * 2)
			    || write(fds[1], "\n", 1) != 1) {
				fprintf(stderr, "prime: submitblock write failed\n");
			}
		}
		close(fds[1]);
		{
			int st = 0;
			if (waitpid(pid, &st, 0) == pid && WIFEXITED(st) && WEXITSTATUS(st) == 0) {
				fprintf(stderr, "prime: submitblock accepted %s\n", hash_disp);
				rc = 0;
			} else {
				fprintf(stderr, "prime: submitblock failed for %s (exit %d)\n",
					hash_disp, WIFEXITED(st) ? WEXITSTATUS(st) : -1);
			}
		}
	}
	free(hex);
	return rc;
}

int prime_encode_coinbaser_outputs(uint64_t value, uint8_t coinbaser_id,
				   const uint64_t *values, const unsigned char *const *scripts,
				   const size_t *script_lens, size_t nout,
				   const unsigned char *prevhash,
				   unsigned char **out, size_t *out_len)
{
	size_t blob_len = 1;
	size_t i, n;
	unsigned char *p;
	uint64_t total = 0;
	size_t extra = prevhash ? PRIME_COINBASER_PREVHASH_TRAILER_LEN : 0;

	*out = NULL;
	*out_len = 0;
	for (i = 0; i < nout; i++) {
		if (!scripts[i] || script_lens[i] < 2 || script_lens[i] > 64 || !values[i]) {
			continue;
		}
		blob_len += 8 + 1 + script_lens[i];
		total += values[i];
	}
	if (total > value) {
		return -1;
	}
	n = 1 + 8 + 4 + blob_len + extra;
	p = malloc(n);
	if (!p) {
		return -1;
	}
	p[0] = PRIME_MINING_COINBASER_RESP;
	wr_u64(p + 1, value);
	wr_u32(p + 9, (uint32_t)blob_len);
	p[13] = coinbaser_id;
	{
		size_t o = 14;
		for (i = 0; i < nout; i++) {
			if (!scripts[i] || script_lens[i] < 2 || script_lens[i] > 64 || !values[i]) {
				continue;
			}
			wr_u64(p + o, values[i]);
			o += 8;
			p[o++] = (unsigned char)script_lens[i];
			memcpy(p + o, scripts[i], script_lens[i]);
			o += script_lens[i];
		}
		if (prevhash) {
			memcpy(p + o, PRIME_COINBASER_PREVHASH_MAGIC, PRIME_COINBASER_PREVHASH_MAGIC_LEN);
			memcpy(p + o + PRIME_COINBASER_PREVHASH_MAGIC_LEN, prevhash, 32);
		}
	}
	*out = p;
	*out_len = n;
	return 0;
}

int prime_encode_coinbaser_response(uint64_t value, uint8_t coinbaser_id,
				    const unsigned char *script, size_t script_len,
				    const unsigned char *prevhash,
				    unsigned char **out, size_t *out_len)
{
	return prime_encode_coinbaser_outputs(value, coinbaser_id, &value, &script, &script_len, 1,
					      prevhash, out, out_len);
}

static int encode_share_resp_abw(uint8_t status, uint16_t reason, uint32_t nonce,
				 uint8_t target_byte, uint8_t job_id,
				 const unsigned char *raw_le, uint8_t slot,
				 unsigned char **out, size_t *out_len)
{
	size_t n = raw_le ? 45 : 10;
	unsigned char *p = malloc(n);
	if (!p) {
		return -1;
	}
	p[0] = PRIME_MINING_SHARE_RESP;
	p[1] = status;
	wr_u16(p + 2, reason);
	wr_u32(p + 4, nonce);
	p[8] = target_byte;
	p[9] = job_id;
	if (raw_le) {
		p[10] = PRIME_SHARE_ABW_MARKER;
		p[11] = slot;
		memcpy(p + 12, raw_le, 32);
		p[44] = PRIME_STRUCT_END;
	}
	*out = p;
	*out_len = n;
	return 0;
}

static int encode_share_resp(uint8_t status, uint16_t reason, uint32_t nonce,
			     uint8_t target_byte, uint8_t job_id,
			     unsigned char **out, size_t *out_len)
{
	return encode_share_resp_abw(status, reason, nonce, target_byte, job_id, NULL, 0xff,
				     out, out_len);
}

static int on_coinbaser(prime_conn_mining *st, const prime_config_opts *opt,
			const unsigned char *plain, size_t plain_len,
			unsigned char **payload, size_t *payload_len, const char *peer)
{
	uint64_t value;
	if (plain_len < 1 + 8 + 32 + 1 || plain[0] != PRIME_MINING_COINBASER_REQ) {
		return -1;
	}
	value = rd_u64(plain + 1);
	if (plain[1 + 8 + 32] != PRIME_STRUCT_END) {
		return -1;
	}
	fprintf(stderr, "[%s] coinbaser request %llu sats\n",
		peer && peer[0] ? peer : "?", (unsigned long long)value);
	if (opt->bitcoin_datadir && !prime_parent_have(opt->bitcoin_datadir, plain + 9)) {
		memcpy(st->parent_need, plain + 9, 32);
		st->parent_job = 0;
		st->want_parent = 1;
		fprintf(stderr, "prime: parent not in node; will request 0x14\n");
	}
	{
		uint8_t id = st->next_coinbaser_id ? st->next_coinbaser_id : 1;
		char idents[PRIME_MAX_SPLIT_OUTPUTS][PRIME_MAX_IDENTITY];
		uint64_t amounts[PRIME_MAX_SPLIT_OUTPUTS];
		unsigned char scripts[PRIME_MAX_SPLIT_OUTPUTS][83];
		const unsigned char *script_ptrs[PRIME_MAX_SPLIT_OUTPUTS];
		size_t script_lens[PRIME_MAX_SPLIT_OUTPUTS];
		size_t n = 0, i, kept = 0;
		st->next_coinbaser_id = (uint8_t)(id == 255 ? 1 : id + 1);
		if (opt->pool) {
			n = prime_pool_split(opt->pool, value, idents, amounts,
					     PRIME_MAX_SPLIT_OUTPUTS);
		}
		for (i = 0; i < n; i++) {
			if (prime_address_script(idents[i], scripts[kept], &script_lens[kept],
						 sizeof scripts[kept]) == 0) {
				script_ptrs[kept] = scripts[kept];
				amounts[kept] = amounts[i];
				kept++;
			} else {
				fprintf(stderr, "prime: %s not a payable address; remainder to pool\n",
					idents[i]);
			}
		}
		{
			prime_split_rec *r = split_slot_for(st, id);
			memset(r, 0, sizeof *r);
			r->id = id;
			r->sent_at = time(NULL);
			r->n = kept;
			for (i = 0; i < kept; i++) {
				r->values[i] = amounts[i];
				r->script_lens[i] = script_lens[i];
				memcpy(r->scripts[i], scripts[i], script_lens[i]);
			}
		}
		st->last_coinbaser_id = id;
		if (!kept) {
			return prime_encode_coinbaser_response(value, id, opt->payout_script,
							      opt->payout_script_len, plain + 9,
							      payload, payload_len);
		}
		fprintf(stderr, "[%s] split %zu miner output(s) of %llu sats\n",
			peer && peer[0] ? peer : "?", kept, (unsigned long long)value);
		return prime_encode_coinbaser_outputs(value, id, amounts, script_ptrs, script_lens,
						      kept, plain + 9, payload, payload_len);
	}
}

static int install_job(prime_conn_mining *st, const unsigned char *p, size_t n, size_t *used)
{
	size_t i = 0;
	uint8_t mc;
	unsigned k;
	if (n < 32 + 2 + 4 + 1 + 4 + 8 + 16 + 1) {
		return -1;
	}
	memcpy(st->prev_hash, p, 32);
	i += 32;
	st->target_byte_index = rd_u16(p + i);
	i += 2;
	memcpy(st->nbits, p + i, 4);
	i += 4;
	st->job_coinbaser_id = p[i++];
	st->height = rd_u32(p + i);
	i += 4;
	st->coinbase_value = rd_u64(p + i);
	i += 8;
	st->txn_count = rd_u32(p + i);
	i += 4;
	i += 12;
	mc = p[i++];
	if (mc > PRIME_MAX_MERKLE || i + (size_t)mc * 32 > n) {
		return -1;
	}
	st->merkle_count = mc;
	for (k = 0; k < mc; k++) {
		memcpy(st->merkle[k], p + i, 32);
		i += 32;
	}
	st->have_job = 1;
	*used = i;
	return 0;
}

static int install_coinbase(prime_conn_mining *st, const unsigned char *p, size_t n, size_t *used)
{
	uint16_t l1, l2;
	if (n < 5) {
		return -1;
	}
	st->cb_id = p[0];
	l1 = rd_u16(p + 1);
	l2 = rd_u16(p + 3);
	if ((size_t)5 + l1 + l2 > n) {
		return -1;
	}
	free(st->coinb1);
	free(st->coinb2);
	st->coinb1 = malloc(l1 ? l1 : 1);
	st->coinb2 = malloc(l2 ? l2 : 1);
	if (!st->coinb1 || !st->coinb2) {
		return -1;
	}
	if (l1) {
		memcpy(st->coinb1, p + 5, l1);
	}
	if (l2) {
		memcpy(st->coinb2, p + 5 + l1, l2);
	}
	st->coinb1_len = l1;
	st->coinb2_len = l2;
	st->have_cb = 1;
	*used = (size_t)5 + l1 + l2;
	return 0;
}

static int verify_pow(prime_conn_mining *st, uint8_t target_byte, uint32_t version,
		      int use_time_offset, const unsigned char extranonce[12],
		      const unsigned char sia_ntime[8], const unsigned char sia_nonce[8],
		      uint32_t time_on_wire, int subsidy_only, const unsigned char xor_key[16],
		      unsigned char header[PRIME_HEADER_V2_SIZE], unsigned char result[32],
		      unsigned char merkle[32], unsigned char **coinbase, size_t *coinbase_len,
		      int *meets_network)
{
	unsigned char tx[65536];
	size_t tx_len;
	unsigned char txid[32];
	unsigned char en16[16];
	unsigned char pot[32];
	unsigned char net[32];
	unsigned char mm_rhs[32];
	unsigned char z16[16];
	uint32_t nonce, nonce2, nonce3, time_offset, bits;
	uint16_t txcount;
	uint8_t flags = use_time_offset ? 4 : 0;

	*coinbase = NULL;
	*coinbase_len = 0;
	*meets_network = 0;
	if (!st->have_job || !st->have_cb) {
		return REJECT_BAD_JOB;
	}
	if ((size_t)st->target_byte_index >= st->coinb1_len + 12 + st->coinb2_len) {
		return REJECT_OTHER;
	}
	tx_len = st->coinb1_len + 12 + st->coinb2_len;
	if (tx_len > sizeof tx) {
		return REJECT_OTHER;
	}
	/* Header-v2: extranonce is in the header. Coinbase merkle uses twelve zeros. */
	memcpy(tx, st->coinb1, st->coinb1_len);
	memset(tx + st->coinb1_len, 0, 12);
	memcpy(tx + st->coinb1_len + 12, st->coinb2, st->coinb2_len);
	tx[st->target_byte_index] = target_byte;
	prime_sha256d(tx, tx_len, txid);
	prime_merkle_root(txid, st->merkle, subsidy_only ? 0 : st->merkle_count, merkle);

	memset(en16, 0, 4);
	memcpy(en16 + 4, extranonce, 12);
	nonce = rd_u32(sia_nonce);
	nonce2 = rd_u32(sia_nonce + 4);
	time_offset = rd_u32(sia_ntime);
	nonce3 = rd_u32(sia_ntime + 4);
	bits = rd_u32(st->nbits);
	txcount = (uint16_t)(subsidy_only ? 1 : st->txn_count + 1);
	memset(mm_rhs, 0, sizeof mm_rhs);
	memset(z16, 0, sizeof z16);
	if (prime_header_pow_hash_abw(st->prev_hash, merkle, version, time_on_wire, bits,
				      nonce, nonce2, nonce3, time_offset, en16, txcount, flags,
				      (int32_t)st->height, mm_rhs, xor_key ? xor_key : z16,
				      target_byte, result) != 0) {
		return REJECT_OTHER;
	}
	prime_target_for_pot(target_byte, pot);
	if (!prime_meets_target(result, pot)) {
		char hash_hex[65];
		char pot_hex[65];
		prime_hex_encode(result, 32, hash_hex, sizeof hash_hex);
		prime_hex_encode(pot, 32, pot_hex, sizeof pot_hex);
		fprintf(stderr, "prime: highhash pot=%u flags=%u height=%u txcount=%u hash=%s target=%s\n",
			(unsigned)target_byte, (unsigned)flags, (unsigned)st->height,
			(unsigned)txcount, hash_hex, pot_hex);
		return REJECT_HIGH_HASH;
	}
	prime_header_v2_serialize(header, version, st->prev_hash, merkle, time_on_wire, bits,
				  nonce, nonce2, nonce3, en16, time_offset, txcount, flags, 0, z16,
				  (int32_t)st->height, mm_rhs);
	*coinbase = malloc(tx_len);
	if (!*coinbase) {
		return REJECT_OTHER;
	}
	memcpy(*coinbase, tx, tx_len);
	*coinbase_len = tx_len;
	if (prime_bits_to_target(bits, net) == 0 && prime_meets_target(result, net)) {
		*meets_network = 1;
	}
	return 0;
}

static int stash_or_submit_block(prime_conn_mining *st, const prime_config_opts *opt,
				 uint8_t job_id, int subsidy_only,
				 const unsigned char header[PRIME_HEADER_V2_SIZE],
				 const unsigned char result[32], const unsigned char merkle[32],
				 unsigned char *coinbase, size_t coinbase_len, int *want_txns)
{
	unsigned char *block = NULL;
	size_t block_len = 0;

	*want_txns = 0;
	if (subsidy_only || st->txn_count == 0) {
		if (prime_serialize_block(header, coinbase, coinbase_len, NULL, NULL, 0,
					  &block, &block_len) == 0) {
			prime_submit_block(opt, block, block_len, result);
			free(block);
		}
		free(coinbase);
		return 0;
	}
	clear_pending_block(st);
	st->have_pending_block = 1;
	st->pending_job_id = job_id;
	memcpy(st->pending_header, header, PRIME_HEADER_V2_SIZE);
	memcpy(st->pending_merkle, merkle, 32);
	memcpy(st->pending_hash, result, 32);
	st->pending_coinbase = coinbase;
	st->pending_coinbase_len = coinbase_len;
	st->pending_txn_count = st->txn_count;
	st->pending_height = st->height;
	*want_txns = 1;
	fprintf(stderr, "prime: requesting %u template txns for job %u height %u\n",
		(unsigned)st->txn_count, (unsigned)job_id, (unsigned)st->height);
	return 0;
}

static int on_share(prime_conn_mining *st, const prime_config_opts *opt,
		    const unsigned char *plain, size_t plain_len,
		    unsigned char **payload, size_t *payload_len, int *want_txns,
		    uint8_t *txn_job, const char *peer)
{
	size_t i;
	uint8_t job_id, coinbase_id, flags, target_byte, en_size;
	uint32_t ntime, nonce, version;
	int is_block, subsidy_only, use_time_offset;
	unsigned char extranonce[12];
	const unsigned char *ua;
	unsigned char sia_ntime[8], sia_nonce[8];
	uint32_t time_on_wire = 0;
	int have_blake = 0;
	int rc;
	uint16_t reason = 0;
	uint8_t status;
	uint64_t share_diff;
	unsigned char header[PRIME_HEADER_V2_SIZE];
	unsigned char result[32];
	unsigned char merkle[32];
	unsigned char *coinbase = NULL;
	size_t coinbase_len = 0;
	int meets_network = 0;

	*want_txns = 0;
	*txn_job = 0;
	st->last_accepted = 0;
	st->last_candidate = 0;

	if (plain_len < 18 || plain[0] != PRIME_MINING_SUBMIT_POW) {
		return encode_share_resp(PRIME_SHARE_REJECTED, REJECT_OTHER, 0, 0xff, 0,
					 payload, payload_len);
	}
	i = 1;
	job_id = plain[i++];
	coinbase_id = plain[i++];
	(void)coinbase_id;
	flags = plain[i++];
	target_byte = plain[i++];
	ntime = rd_u32(plain + i);
	i += 4;
	nonce = rd_u32(plain + i);
	i += 4;
	version = rd_u32(plain + i);
	i += 4;
	en_size = plain[i++];
	is_block = flags & 1;
	subsidy_only = (flags & 2) != 0;
	if (en_size != PRIME_EXTRANONCE_SIZE || i + 12 > plain_len) {
		return encode_share_resp(PRIME_SHARE_REJECTED, REJECT_BAD_EN, nonce, target_byte,
					 job_id, payload, payload_len);
	}
	memcpy(extranonce, plain + i, 12);
	i += 12;
	ua = plain + i;
	while (i < plain_len && plain[i] != 0) {
		i++;
	}
	if (i >= plain_len) {
		return encode_share_resp(PRIME_SHARE_REJECTED, 14, nonce, target_byte, job_id,
					 payload, payload_len);
	}
	i++;
	if (i + 4 > plain_len) {
		return encode_share_resp(PRIME_SHARE_REJECTED, REJECT_OTHER, nonce, target_byte,
					 job_id, payload, payload_len);
	}
	use_time_offset = (plain[i] & 1) != 0;
	i += 4;

	while (i < plain_len) {
		uint8_t mark = plain[i++];
		size_t used = 0;
		if (mark == PRIME_STRUCT_END) {
			break;
		}
		if (mark == SECTION_JOB) {
			if (install_job(st, plain + i, plain_len - i, &used) != 0) {
				reason = REJECT_BAD_JOB;
				break;
			}
			i += used;
			if (opt->bitcoin_datadir && st->have_job
			    && !prime_parent_have(opt->bitcoin_datadir, st->prev_hash)) {
				memcpy(st->parent_need, st->prev_hash, 32);
				st->parent_job = job_id;
				st->want_parent = 1;
				fprintf(stderr, "prime: parent not in node; will request 0x14\n");
			}
		} else if (mark == SECTION_COINBASE) {
			if (install_coinbase(st, plain + i, plain_len - i, &used) != 0) {
				reason = REJECT_OTHER;
				break;
			}
			i += used;
		} else if (mark == SECTION_BLAKE2B) {
			if (i + 1 + 8 + 8 + 1 + 4 > plain_len || plain[i] != BLAKE2B_ALGORITHM) {
				reason = REJECT_BLAKE;
				break;
			}
			i++;
			memcpy(sia_ntime, plain + i, 8);
			i += 8;
			memcpy(sia_nonce, plain + i, 8);
			i += 8;
			if (plain[i++] != BLAKE2B_TIME) {
				reason = REJECT_BLAKE;
				break;
			}
			time_on_wire = rd_u32(plain + i);
			i += 4;
			have_blake = 1;
		} else if (mark == SECTION_ABW_SLOT) {
			if (i >= plain_len) {
				reason = REJECT_OTHER;
				break;
			}
			st->abw_slot = plain[i++];
			st->have_abw_slot = 1;
		} else {
			reason = REJECT_OTHER;
			break;
		}
	}

	share_diff = 1ull << (target_byte & 63);
	if (!reason && share_diff < opt->min_difficulty) {
		reason = 13;
	}
	if (!reason && !have_blake) {
		reason = REJECT_BLAKE;
	}
	if (!reason) {
		unsigned char xor_key[16];
		memset(xor_key, 0, sizeof xor_key);
		if (st->abw_on) {
			uint8_t slot = st->have_abw_slot ? st->abw_slot : st->abw.active;
			if (prime_abw_key(&st->abw, slot, xor_key) != 0) {
				reason = PRIME_REJECT_ABW_SLOT;
			}
		}
		if (!reason) {
			rc = verify_pow(st, target_byte, version, use_time_offset, extranonce,
					sia_ntime, sia_nonce, time_on_wire, subsidy_only, xor_key,
					header, result, merkle, &coinbase, &coinbase_len,
					&meets_network);
			if (rc != 0) {
				reason = (uint16_t)rc;
			}
		}
	}
	if (!reason && opt->pool && !prime_pool_replay_new(opt->pool, result)) {
		reason = PRIME_REJECT_DUP;
	}
	if (!reason && opt->require_split
	    && prime_require_split_rejected(st, subsidy_only, meets_network, coinbase,
					    coinbase_len, time(NULL))) {
		reason = PRIME_REJECT_NO_SPLIT;
		if (opt->pool) {
			prime_pool_replay_forget(opt->pool, result);
		}
	}
	status = reason ? PRIME_SHARE_REJECTED : PRIME_SHARE_ACCEPTED;
	st->last_accepted = (status == PRIME_SHARE_ACCEPTED);
	st->last_candidate = st->last_accepted && meets_network;
	if (st->last_accepted) {
		memcpy(st->last_hash, result, 32);
	}
	fprintf(stderr, "[%s] share job=%u user=%.48s diff=%llu %s%s%s reason=%u\n",
		peer && peer[0] ? peer : "?", job_id, (const char *)ua,
		(unsigned long long)share_diff,
		status == PRIME_SHARE_ACCEPTED ? "accept" : "reject",
		is_block ? " flagged-block" : "",
		meets_network ? " NETWORK" : "", (unsigned)reason);
	if (status == PRIME_SHARE_ACCEPTED && opt->pool) {
		char ident[PRIME_MAX_IDENTITY];
		prime_identity_of((const char *)ua, ident, sizeof ident);
		prime_pool_record_share(opt->pool, ident, share_diff, result, opt->coinbase_tag);
	}
	if (status == PRIME_SHARE_ACCEPTED && meets_network) {
		char ident[PRIME_MAX_IDENTITY];
		prime_identity_of((const char *)ua, ident, sizeof ident);
		if (opt->pool) {
			char idents[PRIME_MAX_SPLIT_OUTPUTS][PRIME_MAX_IDENTITY];
			uint64_t amounts[PRIME_MAX_SPLIT_OUTPUTS];
			size_t n = 0, k;
			uint64_t paid = 0;
			n = prime_pool_split(opt->pool, st->coinbase_value, idents, amounts,
					     PRIME_MAX_SPLIT_OUTPUTS);
			for (k = 0; k < n; k++) {
				paid += amounts[k];
			}
			prime_pool_record_block(opt->pool, st->height, result, ident, paid,
						st->coinbase_value > paid
							? st->coinbase_value - paid
							: 0);
			if (n) {
				prime_pool_record_owed(opt->pool, st->height, result, ident, paid,
						       idents, amounts, n);
			}
		}
		stash_or_submit_block(st, opt, job_id, subsidy_only, header, result, merkle,
				      coinbase, coinbase_len, want_txns);
		if (*want_txns) {
			*txn_job = job_id;
		}
		coinbase = NULL;
	} else if (status == PRIME_SHARE_ACCEPTED && is_block) {
		fprintf(stderr, "prime: gateway flagged a block but hash misses nbits\n");
	}
	free(coinbase);
	(void)ntime;
	if (status == PRIME_SHARE_ACCEPTED && st->abw_on) {
		unsigned char raw_le[32];
		int i;
		for (i = 0; i < 32; i++) {
			raw_le[i] = result[31 - i];
		}
		return encode_share_resp_abw(status, reason, nonce, target_byte, job_id, raw_le,
					     st->have_abw_slot ? st->abw_slot : st->abw.active,
					     payload, payload_len);
	}
	return encode_share_resp(status, reason, nonce, target_byte, job_id, payload, payload_len);
}

static int merkle_of_txns(const unsigned char *coinbase, size_t coinbase_len,
			  const unsigned char *const *txns, const size_t *txn_lens, size_t txn_n,
			  unsigned char out[32])
{
	unsigned char *ids;
	unsigned char acc[32];
	size_t i, n, level_n;
	int mutated = 0;

	n = txn_n + 1;
	ids = malloc((n + 1) * 32);
	if (!ids) {
		return -1;
	}
	prime_sha256d(coinbase, coinbase_len, ids);
	for (i = 0; i < txn_n; i++) {
		if (prime_txid(txns[i], txn_lens[i], ids + (i + 1) * 32) != 0) {
			free(ids);
			return -1;
		}
	}
	level_n = n;
	while (level_n > 1) {
		size_t j;
		for (j = 0; j + 1 < level_n; j += 2) {
			if (memcmp(ids + j * 32, ids + (j + 1) * 32, 32) == 0) {
				mutated = 1;
			}
		}
		if (level_n % 2 == 1) {
			memcpy(ids + level_n * 32, ids + (level_n - 1) * 32, 32);
			level_n++;
		}
		for (j = 0; j < level_n; j += 2) {
			unsigned char pair[64];
			memcpy(pair, ids + j * 32, 32);
			memcpy(pair + 32, ids + (j + 1) * 32, 32);
			prime_sha256d(pair, 64, acc);
			memcpy(ids + (j / 2) * 32, acc, 32);
		}
		level_n /= 2;
	}
	memcpy(out, ids, 32);
	free(ids);
	return mutated ? -2 : 0;
}

static int on_validation(prime_conn_mining *st, const prime_config_opts *opt,
			 const unsigned char *plain, size_t plain_len)
{
	size_t i;
	uint8_t job_id, status;
	uint16_t stated;
	unsigned k;
	const unsigned char **txns = NULL;
	size_t *lens = NULL;
	unsigned char *block = NULL;
	size_t block_len = 0;
	unsigned char merkle[32];

	if (plain_len < 4 || plain[0] != PRIME_MINING_VALIDATION) {
		return 0;
	}
	if (plain[1] == PRIME_VAL_RESP_SHORT_TXNS || plain[1] == PRIME_VAL_RESP_TXNS) {
		fprintf(stderr, "prime: job validation %02x job=%u status=%02x (%zu bytes)\n",
			plain[1], plain_len > 2 ? plain[2] : 0, plain_len > 3 ? plain[3] : 0,
			plain_len);
		return 0;
	}
	if (plain[1] == PRIME_VAL_RESP_PARENT) {
		uint8_t status;
		uint32_t blen;
		if (plain_len < 42) {
			return 0;
		}
		status = plain[3];
		blen = rd_u32(plain + 36);
		fprintf(stderr, "prime: parent fetch job=%u status=%02x %u bytes\n",
			plain[2], status, blen);
		if (status == 0x01 && blen && 40 + blen < plain_len && opt->bitcoin_datadir) {
			prime_submit_raw_block(opt->bitcoin_datadir, plain + 40, blen);
		}
		return 0;
	}
	if (plain[1] != PRIME_VAL_RESP_BLOCK_TXNS) {
		fprintf(stderr, "prime: unhandled validation %02x\n", plain[1]);
		return 0;
	}
	job_id = plain[2];
	status = plain[3];
	if (!st->have_pending_block || st->pending_job_id != job_id) {
		fprintf(stderr, "prime: unexpected block txns job=%u status=%02x\n",
			(unsigned)job_id, (unsigned)status);
		return 0;
	}
	if (status != 0x01) {
		fprintf(stderr, "prime: gateway refused block txns job=%u status=%02x\n",
			(unsigned)job_id, (unsigned)status);
		clear_pending_block(st);
		return 0;
	}
	if (plain_len < 6) {
		clear_pending_block(st);
		return 0;
	}
	stated = rd_u16(plain + 4);
	i = 6;
	if (stated != st->pending_txn_count) {
		fprintf(stderr, "prime: txn count %u != pending %u\n",
			(unsigned)stated, (unsigned)st->pending_txn_count);
	}
	txns = calloc(stated ? stated : 1, sizeof *txns);
	lens = calloc(stated ? stated : 1, sizeof *lens);
	if (!txns || !lens) {
		free(txns);
		free(lens);
		clear_pending_block(st);
		return -1;
	}
	for (k = 0; k < stated; k++) {
		uint32_t sz;
		if (i + 3 > plain_len) {
			fprintf(stderr, "prime: truncated txn list at %u\n", k);
			free(txns);
			free(lens);
			clear_pending_block(st);
			return 0;
		}
		sz = (uint32_t)rd_u16(plain + i) | ((uint32_t)plain[i + 2] << 16);
		i += 3;
		if (i + sz > plain_len) {
			fprintf(stderr, "prime: txn %u overruns message\n", k);
			free(txns);
			free(lens);
			clear_pending_block(st);
			return 0;
		}
		txns[k] = plain + i;
		lens[k] = sz;
		i += sz;
	}
	if (i >= plain_len || plain[i] != PRIME_STRUCT_END) {
		fprintf(stderr, "prime: block txn list missing terminator\n");
		free(txns);
		free(lens);
		clear_pending_block(st);
		return 0;
	}
	if (merkle_of_txns(st->pending_coinbase, st->pending_coinbase_len, txns, lens, stated,
			   merkle) != 0
	    || memcmp(merkle, st->pending_merkle, 32) != 0) {
		char got[65], want[65];
		prime_hex_encode(merkle, 32, got, sizeof got);
		prime_hex_encode(st->pending_merkle, 32, want, sizeof want);
		fprintf(stderr, "prime: merkle mismatch after txns got=%s want=%s\n", got, want);
		free(txns);
		free(lens);
		clear_pending_block(st);
		return 0;
	}
	if (prime_serialize_block(st->pending_header, st->pending_coinbase, st->pending_coinbase_len,
				  txns, lens, stated, &block, &block_len) == 0) {
		prime_submit_block(opt, block, block_len, st->pending_hash);
		free(block);
	}
	free(txns);
	free(lens);
	clear_pending_block(st);
	return 0;
}

static int append_mining(prime_session *s, unsigned char **wire, size_t *wire_len,
			 const unsigned char *payload, size_t payload_len)
{
	unsigned char *rw = NULL;
	size_t rwl = 0;
	if (!payload || !payload_len) {
		return 0;
	}
	if (prime_session_encrypt(s, PRIME_CMD_MINING, payload, payload_len, false, &rw, &rwl) != 0
	    || !rw) {
		return -1;
	}
	if (!*wire) {
		*wire = rw;
		*wire_len = rwl;
		return 0;
	}
	{
		unsigned char *both = malloc(*wire_len + rwl);
		if (!both) {
			free(rw);
			return -1;
		}
		memcpy(both, *wire, *wire_len);
		memcpy(both + *wire_len, rw, rwl);
		free(*wire);
		free(rw);
		*wire = both;
		*wire_len += rwl;
	}
	return 0;
}

static void send_parent_fetch(prime_session *s, prime_conn_mining *st,
			      unsigned char **wire, size_t *wire_len)
{
	unsigned char req[35];
	if (!st->want_parent) {
		return;
	}
	req[0] = PRIME_MINING_VALIDATION;
	req[1] = PRIME_VAL_REQ_PARENT;
	req[2] = st->parent_job;
	memcpy(req + 3, st->parent_need, 32);
	if (append_mining(s, wire, wire_len, req, 35) == 0) {
		fprintf(stderr, "prime: requested parent fetch (0x50 0x14) job=%u\n",
			(unsigned)st->parent_job);
	}
	st->want_parent = 0;
}

int prime_handle_mining(prime_session *s, prime_conn_mining *st, const prime_config_opts *opt,
			const unsigned char *plain, size_t plain_len,
			unsigned char **wire, size_t *wire_len, const char *peer)
{
	unsigned char *payload = NULL;
	size_t payload_len = 0;
	int rc;

	*wire = NULL;
	*wire_len = 0;
	if (!plain_len) {
		return 0;
	}
	if (plain[0] == PRIME_MINING_COINBASER_REQ) {
		if (on_coinbaser(st, opt, plain, plain_len, &payload, &payload_len, peer) != 0) {
			return -1;
		}
		rc = prime_session_encrypt(s, PRIME_CMD_MINING, payload, payload_len, false, wire, wire_len);
		free(payload);
		if (rc == 0) {
			send_parent_fetch(s, st, wire, wire_len);
		}
		return rc;
	}
	if (plain[0] == PRIME_MINING_SUBMIT_POW) {
		int want_txns = 0;
		uint8_t txn_job = 0;
		if (on_share(st, opt, plain, plain_len, &payload, &payload_len, &want_txns,
			     &txn_job, peer) != 0) {
			return -1;
		}
		rc = prime_session_encrypt(s, PRIME_CMD_MINING, payload, payload_len, false, wire, wire_len);
		if (rc == 0 && st->last_accepted && st->abw_on) {
			unsigned char raw_le[32], *extra = NULL;
			size_t extra_len = 0, k;
			unsigned char *rot = NULL, **revs = NULL;
			size_t rot_len = 0, *rlens = NULL, rn = 0;
			int i;
			for (i = 0; i < 32; i++) {
				raw_le[i] = st->last_hash[31 - i];
			}
			if (st->last_candidate
			    && prime_abw_encode_receipt(st->have_abw_slot ? st->abw_slot : st->abw.active,
							raw_le, &extra, &extra_len) == 0
			    && extra) {
				unsigned char *rw = NULL;
				size_t rwl = 0;
				if (prime_session_encrypt(s, PRIME_CMD_MINING, extra, extra_len,
							  false, &rw, &rwl) == 0 && rw) {
					unsigned char *both = malloc(*wire_len + rwl);
					if (both) {
						memcpy(both, *wire, *wire_len);
						memcpy(both + *wire_len, rw, rwl);
						free(*wire);
						*wire = both;
						*wire_len += rwl;
					}
					free(rw);
				}
				free(extra);
			}
			prime_abw_on_share(&st->abw, &rot, &rot_len);
			if (rot && rot_len) {
				unsigned char *rw = NULL;
				size_t rwl = 0;
				if (prime_session_encrypt(s, PRIME_CMD_MINING, rot, rot_len, false,
							  &rw, &rwl) == 0 && rw) {
					unsigned char *both = malloc(*wire_len + rwl);
					if (both) {
						memcpy(both, *wire, *wire_len);
						memcpy(both + *wire_len, rw, rwl);
						free(*wire);
						*wire = both;
						*wire_len += rwl;
					}
					free(rw);
				}
				free(rot);
			}
			prime_abw_due_reveals(&st->abw, &revs, &rlens, &rn);
			for (k = 0; k < rn; k++) {
				unsigned char *rw = NULL;
				size_t rwl = 0;
				if (prime_session_encrypt(s, PRIME_CMD_MINING, revs[k], rlens[k],
							  false, &rw, &rwl) == 0 && rw) {
					unsigned char *both = malloc(*wire_len + rwl);
					if (both) {
						memcpy(both, *wire, *wire_len);
						memcpy(both + *wire_len, rw, rwl);
						free(*wire);
						*wire = both;
						*wire_len += rwl;
					}
					free(rw);
				}
				free(revs[k]);
			}
			free(revs);
			free(rlens);
		}
		free(payload);
		if (rc == 0 && want_txns) {
			unsigned char req[3];
			unsigned char *req_wire = NULL;
			size_t req_len = 0;
			req[0] = PRIME_MINING_VALIDATION;
			req[1] = PRIME_VAL_REQ_BLOCK_TXNS;
			req[2] = txn_job;
			if (prime_session_encrypt(s, PRIME_CMD_MINING, req, 3, false, &req_wire,
						  &req_len) == 0 && req_wire) {
				unsigned char *both = malloc(*wire_len + req_len);
				if (both) {
					memcpy(both, *wire, *wire_len);
					memcpy(both + *wire_len, req_wire, req_len);
					free(*wire);
					*wire = both;
					*wire_len += req_len;
				}
				free(req_wire);
			}
		}
		if (rc == 0) {
			send_parent_fetch(s, st, wire, wire_len);
		}
		return rc;
	}
	if (plain[0] == PRIME_MINING_VALIDATION) {
		return on_validation(st, opt, plain, plain_len);
	}
	fprintf(stderr, "[%s] unhandled mining sub %02x (%zu bytes)\n",
		peer && peer[0] ? peer : "?", plain[0], plain_len);
	return 0;
}
