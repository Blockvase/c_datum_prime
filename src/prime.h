/* c_datum_prime (C)
 * Translated from RATUM Prime by iohzrd (https://github.com/iohzrd/ratum).
 * core/src/datum/framing.rs, handshake.rs, messages.rs; prime/src/connection.rs
 * Copyright (C) iohzrd and RATUM contributors
 * Copyright (C) Blockvase contributors (C translation)
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#ifndef BLOCKVASE_PRIME_H
#define BLOCKVASE_PRIME_H

#include <sodium.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>

#define PRIME_MAX_CMD_LEN ((1u << 22) - 1)
#define PRIME_INITIAL_HELLO_KEY 0xDC871829u
#define PRIME_STRUCT_END 0xFEu
#define PRIME_NONCE_LEN 24
#define PRIME_KEYS_LEN 128
#define PRIME_MAX_MOTD 511
#define PRIME_MAX_UA 256
#define PRIME_MAX_HELLO_FRAME 4096
#define PRIME_RESUME_TOKEN_LEN 40
#define PRIME_MAX_PAYOUT_SCRIPT 83
#define PRIME_MAX_COINBASE_TAG 81

#define PRIME_CMD_HELLO_OR_PING 1
#define PRIME_CMD_HANDSHAKE_RESPONSE 2
#define PRIME_CMD_MINING 5
#define PRIME_CMD_BULK 6
#define PRIME_CMD_INFO 7

#define PRIME_MINING_CONFIG 0x99
#define PRIME_CONFIG_V1 1
#define PRIME_CONFIG_V3 3
#define PRIME_CONFIG_FLAG_ABW_DISABLED 0x01

typedef struct {
	uint32_t cmd_len;
	uint8_t reserved;
	bool is_signed;
	bool is_encrypted_pubkey;
	bool is_encrypted_channel;
	uint8_t proto_cmd;
} prime_header;

typedef struct {
	uint32_t key;
} prime_ratchet;

typedef struct {
	unsigned char sign_pk[crypto_sign_PUBLICKEYBYTES];
	unsigned char sign_sk[crypto_sign_SECRETKEYBYTES];
	unsigned char box_pk[crypto_box_PUBLICKEYBYTES];
	unsigned char box_sk[crypto_box_SECRETKEYBYTES];
} prime_keypairs;

typedef enum {
	PRIME_GEN_V1 = 0,
	PRIME_GEN_V3 = 1
} prime_generation;

typedef struct {
	unsigned char client_sign_pk[32];
	unsigned char client_box_pk[32];
	unsigned char session_sign_pk[32];
	unsigned char session_box_pk[32];
	char user_agent[PRIME_MAX_UA + 1];
	uint32_t nk;
	prime_generation generation;
	bool resume_present;
	unsigned char resume_token[PRIME_RESUME_TOKEN_LEN];
} prime_hello;

typedef struct {
	unsigned char precomp[crypto_box_BEFORENMBYTES];
	unsigned char tx_nonce[PRIME_NONCE_LEN];
	unsigned char rx_nonce[PRIME_NONCE_LEN];
	prime_ratchet tx_headers;
	prime_ratchet rx_headers;
	unsigned char session_sign_sk[crypto_sign_SECRETKEYBYTES];
	unsigned char session_sign_pk[crypto_sign_PUBLICKEYBYTES];
	unsigned char peer_session_sign_pk[32];
	bool ready;
} prime_session;

typedef struct {
	const unsigned char *payout_script;
	size_t payout_script_len;
	uint64_t prime_id;
	const char *coinbase_tag;
	uint64_t min_difficulty;
	bool abw_disabled;
	bool require_split;
	bool bulk_framing;
	uint16_t fee_bps;
	bool fee_after_first_block;
	uint64_t min_payout;
	double window_multiple;
	uint64_t window_floor;
	unsigned abw_reveal_after_sec;
	const char *bitcoin_datadir;
	const char *block_dir;
	const char *ledger_path;
	const char *stats_listen;
	struct prime_pool *pool;
} prime_config_opts;

uint32_t prime_feedback(uint32_t i);
void prime_header_to_bytes(const prime_header *h, unsigned char out[4]);
int prime_header_from_bytes(const unsigned char in[4], prime_header *h);
void prime_ratchet_init(prime_ratchet *r, uint32_t key);
void prime_ratchet_hello(prime_ratchet *r);
void prime_ratchet_mask(prime_ratchet *r, const prime_header *h, unsigned char out[4]);
void prime_ratchet_unmask(prime_ratchet *r, const unsigned char in[4], prime_header *h);
void prime_header_keys_from_nk(uint32_t nk, uint32_t *client_to_server, uint32_t *server_to_client);
void prime_derive_nonces(uint32_t nk, const unsigned char session_pk_ed25519[32],
			 unsigned char client_receiver[PRIME_NONCE_LEN],
			 unsigned char client_sender[PRIME_NONCE_LEN]);
void prime_increment_nonce(unsigned char nonce[PRIME_NONCE_LEN]);

int prime_hex_encode(const unsigned char *bin, size_t bin_len, char *out, size_t out_len);
int prime_hex_decode(const char *hex, unsigned char *out, size_t out_len);

int prime_keys_generate(prime_keypairs *k);
int prime_keys_load_or_create(const char *path, prime_keypairs *k);
void prime_keys_pubkey_hex(const prime_keypairs *k, char out[129]);

int prime_open_hello(const prime_header *header, const unsigned char *payload, size_t payload_len,
		     const prime_keypairs *pool, prime_hello *out);
int prime_accept(const prime_hello *hello, const prime_keypairs *pool, const char *motd,
		 unsigned char **wire, size_t *wire_len, prime_session *session);
int prime_session_encrypt(prime_session *s, uint8_t proto_cmd, const unsigned char *payload,
			  size_t payload_len, bool sign, unsigned char **wire, size_t *wire_len);
int prime_session_decrypt(prime_session *s, const prime_header *header,
			  const unsigned char *ciphertext, size_t ciphertext_len,
			  unsigned char **plain, size_t *plain_len);

int prime_encode_config_v1(const prime_config_opts *opt, unsigned char **out, size_t *out_len);
int prime_encode_config_v3(const prime_config_opts *opt, const unsigned char resume_token[PRIME_RESUME_TOKEN_LEN],
			   unsigned char **out, size_t *out_len);
void prime_new_resume_token(uint64_t prime_id, unsigned char token[PRIME_RESUME_TOKEN_LEN]);

int prime_selftest(void);

#define PRIME_MINING_COINBASER_REQ 0x10
#define PRIME_MINING_COINBASER_RESP 0x11
#define PRIME_MINING_SUBMIT_POW 0x27
#define PRIME_MINING_SHARE_RESP 0x8F
#define PRIME_SHARE_ACCEPTED 0x50
#define PRIME_SHARE_REJECTED 0x66
#define PRIME_MINING_VALIDATION 0x50
#define PRIME_VAL_REQ_BLOCK_TXNS 0x12
#define PRIME_VAL_RESP_BLOCK_TXNS 0x92
#define PRIME_HEADER_V2_SIZE 164
#define PRIME_V2_FLAG 0x80000000u
#define PRIME_MAX_MERKLE 24
#define PRIME_EXTRANONCE_SIZE 12
#define PRIME_ABW_SLOTS 16
#define PRIME_MAX_IDENTITY 128
#define PRIME_MAX_SPLIT_OUTPUTS 128

typedef struct {
	int have_key[PRIME_ABW_SLOTS];
	int have_revealed[PRIME_ABW_SLOTS];
	unsigned char keys[PRIME_ABW_SLOTS][16];
	unsigned char revealed[PRIME_ABW_SLOTS][16];
	uint8_t active;
	uint64_t shares;
	time_t activated_at;
	time_t retired_at[PRIME_ABW_SLOTS];
	int retired_sent[PRIME_ABW_SLOTS];
	unsigned reveal_after_sec;
} prime_abw;

typedef struct {
	uint8_t id;
	time_t sent_at;
	size_t n;
	uint64_t values[PRIME_MAX_SPLIT_OUTPUTS];
	unsigned char scripts[PRIME_MAX_SPLIT_OUTPUTS][83];
	size_t script_lens[PRIME_MAX_SPLIT_OUTPUTS];
} prime_split_rec;

typedef struct {
	int have_job;
	unsigned char prev_hash[32];
	uint16_t target_byte_index;
	unsigned char nbits[4];
	uint8_t job_coinbaser_id;
	uint32_t height;
	uint64_t coinbase_value;
	uint32_t txn_count;
	uint8_t merkle_count;
	unsigned char merkle[PRIME_MAX_MERKLE][32];
	int have_cb;
	uint8_t cb_id;
	unsigned char *coinb1;
	size_t coinb1_len;
	unsigned char *coinb2;
	size_t coinb2_len;
	uint8_t next_coinbaser_id;
	uint8_t abw_slot;
	int have_abw_slot;
	uint8_t last_coinbaser_id;
	int abw_on;
	prime_abw abw;
	prime_split_rec splits[16];
	size_t nsplits;
	unsigned char last_hash[32];
	int last_accepted;
	int last_candidate;
	int want_parent;
	uint8_t parent_job;
	unsigned char parent_need[32];
	int have_pending_block;
	uint8_t pending_job_id;
	unsigned char pending_header[PRIME_HEADER_V2_SIZE];
	unsigned char pending_merkle[32];
	unsigned char pending_hash[32];
	unsigned char *pending_coinbase;
	size_t pending_coinbase_len;
	uint32_t pending_txn_count;
	uint32_t pending_height;
} prime_conn_mining;

void prime_conn_mining_init(prime_conn_mining *m);
void prime_conn_mining_free(prime_conn_mining *m);
int prime_require_split_rejected(const prime_conn_mining *st, int subsidy_only,
				 int meets_network, const unsigned char *coinbase,
				 size_t coinbase_len, time_t now);

int prime_encode_coinbaser_response(uint64_t value, uint8_t coinbaser_id,
				    const unsigned char *script, size_t script_len,
				    const unsigned char *prevhash,
				    unsigned char **out, size_t *out_len);
int prime_handle_mining(prime_session *s, prime_conn_mining *st, const prime_config_opts *opt,
			const unsigned char *plain, size_t plain_len,
			unsigned char **wire, size_t *wire_len, const char *peer);

int prime_source_start(const char *listen_addr, const char *public_url);

void prime_sha256d(const unsigned char *in, size_t in_len, unsigned char out[32]);
void prime_merkle_root(const unsigned char coinbase_txid[32],
		       const unsigned char branches[][32], unsigned n, unsigned char out[32]);
void prime_target_for_pot(uint8_t exponent, unsigned char t[32]);
int prime_meets_target(const unsigned char hash[32], const unsigned char target[32]);
int prime_header_pow_hash(const unsigned char prev_block[32], const unsigned char merkle_root[32],
			  uint32_t version, uint32_t time_on_wire, uint32_t bits,
			  uint32_t nonce, uint32_t nonce2, uint32_t nonce3, uint32_t time_offset,
			  const unsigned char extranonce[16], uint16_t txcount, uint8_t flags,
			  int32_t height, const unsigned char mm_rhs[32], unsigned char result[32]);
int prime_bits_to_target(uint32_t bits, unsigned char t[32]);
void prime_header_v2_serialize(unsigned char out[PRIME_HEADER_V2_SIZE],
			       uint32_t version, const unsigned char prev_block[32],
			       const unsigned char merkle_root[32], uint32_t time_on_wire,
			       uint32_t bits, uint32_t nonce, uint32_t nonce2, uint32_t nonce3,
			       const unsigned char extranonce[16], uint32_t time_offset,
			       uint16_t txcount, uint8_t flags, uint8_t xor_clear,
			       const unsigned char xor_key[16], int32_t height,
			       const unsigned char mm_rhs[32]);
size_t prime_encode_compact_size(uint64_t n, unsigned char out[9]);
int prime_txid(const unsigned char *tx, size_t tx_len, unsigned char out[32]);
int prime_serialize_block(const unsigned char header[PRIME_HEADER_V2_SIZE],
			  const unsigned char *coinbase, size_t coinbase_len,
			  const unsigned char *const *txns, const size_t *txn_lens, size_t txn_n,
			  unsigned char **out, size_t *out_len);
int prime_submit_block(const prime_config_opts *opt, const unsigned char *block, size_t block_len,
		       const unsigned char hash[32]);

void prime_tagged_sha256(const char *tag, const unsigned char *data, size_t data_len,
			 unsigned char out[32]);
void prime_xor_key_hash(const unsigned char xor_key[16], unsigned char out[32]);
void prime_xor_mask(const unsigned char xor_key[16], uint8_t clear_bits, unsigned char out[32]);
int prime_header_pow_hash_abw(const unsigned char prev_block[32], const unsigned char merkle_root[32],
			      uint32_t version, uint32_t time_on_wire, uint32_t bits,
			      uint32_t nonce, uint32_t nonce2, uint32_t nonce3, uint32_t time_offset,
			      const unsigned char extranonce[16], uint16_t txcount, uint8_t flags,
			      int32_t height, const unsigned char mm_rhs[32],
			      const unsigned char xor_key[16], uint8_t pot,
			      unsigned char result[32]);

#define PRIME_ABW_RECEIPT 0xA5
#define PRIME_ABW_NOTICE 0xA8
#define PRIME_ABW_REVEAL 0xA9
#define PRIME_ABW_ROTATE_SHARES 16384
#define PRIME_VAL_REQ_SHORT_TXNS 0x10
#define PRIME_VAL_REQ_TXNS 0x11
#define PRIME_VAL_REQ_PARENT 0x14
#define PRIME_VAL_RESP_SHORT_TXNS 0x90
#define PRIME_VAL_RESP_TXNS 0x91
#define PRIME_VAL_RESP_PARENT 0x94
#define PRIME_SHARE_ABW_MARKER 0x06
#define PRIME_REJECT_DUP 29
#define PRIME_REJECT_NO_SPLIT 43
#define PRIME_REJECT_ABW_SLOT 44
#define PRIME_MAX_COINBASER_OUTPUTS 512
#define PRIME_SPLIT_GRACE_SECS 10

typedef struct prime_pool prime_pool;

const char *prime_identity_of(const char *username, char *out, size_t out_len);
int prime_address_script(const char *addr, unsigned char *out, size_t *out_len, size_t max_len);
uint64_t prime_window_for_difficulty(double network_diff, double multiple, uint64_t floor);

prime_pool *prime_pool_open(const char *path, uint64_t window, uint64_t min_payout, uint16_t fee_bps);
void prime_pool_set_fee_after_first_block(prime_pool *p, uint16_t after_bps);
uint16_t prime_pool_fee_bps(const prime_pool *p);
void prime_pool_close(prime_pool *p);
void prime_pool_set_window(prime_pool *p, uint64_t window);
int prime_pool_record_share(prime_pool *p, const char *identity, uint64_t difficulty,
			    const unsigned char hash[32], const char *tag);
int prime_pool_replay_new(prime_pool *p, const unsigned char hash[32]);
void prime_pool_replay_forget(prime_pool *p, const unsigned char hash[32]);
size_t prime_pool_split(prime_pool *p, uint64_t value, char idents[][PRIME_MAX_IDENTITY],
			uint64_t *amounts, size_t max_n);
int prime_pool_record_block(prime_pool *p, uint32_t height, const unsigned char hash[32],
			    const char *finder, uint64_t paid_split, uint64_t paid_pool);
int prime_pool_stats_json(prime_pool *p, char *out, size_t out_len);
uint64_t prime_pool_share_count(const prime_pool *p);
uint64_t prime_pool_total_work(const prime_pool *p);
uint64_t prime_pool_window(const prime_pool *p);
uint64_t prime_pool_blocks_found(const prime_pool *p);
double prime_pool_hashrate_hs(prime_pool *p);
#define PRIME_HASHRATE_WINDOW_SEC 10800
#define PRIME_HASHES_PER_DIFF 4294967296.0

int prime_pool_resume_put(prime_pool *p, const unsigned char token[PRIME_RESUME_TOKEN_LEN],
			  const unsigned char client_pk[32], uint8_t coinbaser_id,
			  const prime_abw *abw);
int prime_pool_resume_get(prime_pool *p, const unsigned char token[PRIME_RESUME_TOKEN_LEN],
			  const unsigned char client_pk[32], uint8_t *coinbaser_id,
			  prime_abw *abw);

void prime_abw_start(prime_abw *a, unsigned reveal_after_sec);
void prime_abw_resumed(prime_abw *a);
int prime_abw_key(const prime_abw *a, uint8_t slot, unsigned char key[16]);
int prime_abw_encode_notice(const prime_abw *a, uint8_t slot, int active,
			    unsigned char **out, size_t *out_len);
int prime_abw_encode_notices(const prime_abw *a, unsigned char ***out, size_t **lens, size_t *n);
int prime_abw_encode_receipt(uint8_t slot, const unsigned char raw_le[32],
			     unsigned char **out, size_t *out_len);
int prime_abw_encode_reveal(uint8_t slot, const unsigned char key[16],
			    unsigned char **out, size_t *out_len);
int prime_abw_on_share(prime_abw *a, unsigned char **rotate_wire, size_t *rotate_len);
int prime_abw_due_reveals(prime_abw *a, unsigned char ***out, size_t **lens, size_t *n);

int prime_encode_coinbaser_outputs(uint64_t value, uint8_t coinbaser_id,
				   const uint64_t *values, const unsigned char *const *scripts,
				   const size_t *script_lens, size_t n,
				   const unsigned char *prevhash,
				   unsigned char **out, size_t *out_len);

int prime_bulk_ack(uint32_t id, uint32_t next_offset, unsigned char out[12]);
int prime_bulk_ingest(unsigned char **acc, size_t *acc_len, size_t *acc_cap, uint32_t *id,
		      uint32_t *total, uint32_t *got, const unsigned char *plain, size_t plain_len,
		      int *complete);

int prime_stats_start(const char *listen_addr, prime_pool *pool, const char *motd,
		      const char *pubkey_hex, const prime_config_opts *opt,
		      const char *datum_host, uint16_t datum_port, const char *source_url);
void prime_stats_client_open(void);
void prime_stats_client_close(void);

int prime_rpc_datadir_arg(const char *datadir, char *out, size_t out_len);
int prime_rpc_call(const char *datadir, const char *rest, char *out, size_t out_len);
int prime_rpc_difficulty(const char *datadir, double *out);
int prime_parent_have(const char *datadir, const unsigned char prev_hash[32]);
int prime_submit_raw_block(const char *datadir, const unsigned char *block, size_t block_len);
int prime_tip_start(const char *datadir, prime_pool *pool, double multiple, uint64_t floor);

int prime_pool_record_owed(prime_pool *p, uint32_t height, const unsigned char hash[32],
			   const char *finder, uint64_t total,
			   const char idents[][PRIME_MAX_IDENTITY], const uint64_t *amounts,
			   size_t n);
int prime_pool_settle(prime_pool *p, const unsigned char hash[32], uint64_t at);
int prime_pool_void_owed(prime_pool *p, const unsigned char hash[32]);
int prime_pool_dump(prime_pool *p, FILE *out);
int prime_pool_list_owed(prime_pool *p, FILE *out);

#endif
