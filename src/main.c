/* c_datum_prime (C)
 * Translated from RATUM Prime (prime/src/connection.rs, prime/src/main.rs) by iohzrd.
 * Copyright (C) iohzrd and RATUM contributors
 * Copyright (C) Blockvase contributors (C translation)
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#define _POSIX_C_SOURCE 200809L
#include "prime.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static volatile sig_atomic_t g_stop = 0;

/* data/ next to the project root (parent of build/), not the cwd or a hardcoded home path. */
static void tree_data_dir(char *out, size_t out_len)
{
	char exe[512];
	char *slash;
	ssize_t n;

	n = readlink("/proc/self/exe", exe, sizeof exe - 1);
	if (n <= 0 || (size_t)n >= sizeof exe - 1) {
		snprintf(out, out_len, "data");
		return;
	}
	exe[n] = 0;
	slash = strrchr(exe, '/');
	if (!slash) {
		snprintf(out, out_len, "data");
		return;
	}
	*slash = 0;
	slash = strrchr(exe, '/');
	if (slash && strcmp(slash, "/build") == 0) {
		*slash = 0;
	}
	snprintf(out, out_len, "%s/data", exe);
}

static void on_signal(int sig)
{
	(void)sig;
	g_stop = 1;
}

static int write_all(int fd, const unsigned char *buf, size_t n)
{
	size_t off = 0;
	while (off < n) {
		ssize_t w = send(fd, buf + off, n - off, MSG_NOSIGNAL);
		if (w < 0) {
			if (errno == EINTR) {
				continue;
			}
			return -1;
		}
		if (w == 0) {
			return -1;
		}
		off += (size_t)w;
	}
	return 0;
}

static int read_exact(int fd, unsigned char *buf, size_t n)
{
	size_t off = 0;
	while (off < n) {
		ssize_t r = recv(fd, buf + off, n - off, 0);
		if (r < 0) {
			if (errno == EINTR) {
				continue;
			}
			return -1;
		}
		if (r == 0) {
			/* Do not leave SO_RCVTIMEO's EAGAIN on EOF; the mining
			 * loop treats that as idle and never drops the client. */
			errno = ECONNRESET;
			return -1;
		}
		off += (size_t)r;
	}
	return 0;
}

static int parse_listen(const char *s, char *host, size_t host_len, uint16_t *port)
{
	const char *colon = strrchr(s, ':');
	size_t n;
	unsigned long p;
	char *end = NULL;
	if (!colon) {
		return -1;
	}
	n = (size_t)(colon - s);
	if (n == 0 || n >= host_len) {
		return -1;
	}
	memcpy(host, s, n);
	host[n] = 0;
	p = strtoul(colon + 1, &end, 10);
	if (!end || *end || p == 0 || p > 65535) {
		return -1;
	}
	*port = (uint16_t)p;
	return 0;
}

static int parse_hex_script(const char *hex, unsigned char *out, size_t *out_len, size_t max_len)
{
	size_t n = strlen(hex);
	if (n == 0 || (n & 1) || n / 2 > max_len) {
		return -1;
	}
	*out_len = n / 2;
	return prime_hex_decode(hex, out, *out_len);
}

static void handle_client(int fd, const struct sockaddr_in *peer, const prime_keypairs *pool,
			  const char *motd, const prime_config_opts *opt, int public_stratum)
{
	unsigned char hdr_bytes[4];
	unsigned char *payload = NULL;
	unsigned char *resp = NULL;
	unsigned char *cfg = NULL;
	unsigned char *cfg_wire = NULL;
	size_t resp_len = 0, cfg_len = 0, cfg_wire_len = 0;
	prime_ratchet hello_rx;
	prime_header header;
	prime_hello hello;
	prime_session session;
	prime_conn_mining mining;
	char peer_s[64];
	unsigned char token[PRIME_RESUME_TOKEN_LEN];
	unsigned char *bulk = NULL;
	size_t bulk_len = 0, bulk_cap = 0;
	uint32_t bid = 0, btot = 0, bgot = 0;
	int counted_client = 0;
	int logged_first_mining = 0;

	snprintf(peer_s, sizeof peer_s, "%s:%u", inet_ntoa(peer->sin_addr), ntohs(peer->sin_port));
	prime_conn_mining_init(&mining);
	mining.public_stratum = public_stratum ? 1 : 0;
	prime_ratchet_hello(&hello_rx);
	if (read_exact(fd, hdr_bytes, 4) != 0) {
		fprintf(stderr, "[%s] no hello header\n", peer_s);
		prime_conn_mining_free(&mining);
		return;
	}
	prime_ratchet_unmask(&hello_rx, hdr_bytes, &header);
	if (header.cmd_len == 0 || header.cmd_len > PRIME_MAX_HELLO_FRAME) {
		fprintf(stderr, "[%s] hello frame too large (%u)\n", peer_s, header.cmd_len);
		prime_conn_mining_free(&mining);
		return;
	}
	payload = malloc(header.cmd_len);
	if (!payload || read_exact(fd, payload, header.cmd_len) != 0) {
		fprintf(stderr, "[%s] hello body read failed\n", peer_s);
		free(payload);
		prime_conn_mining_free(&mining);
		return;
	}
	if (prime_open_hello(&header, payload, header.cmd_len, pool, &hello) != 0) {
		fprintf(stderr, "[%s] hello rejected\n", peer_s);
		free(payload);
		prime_conn_mining_free(&mining);
		return;
	}
	free(payload);
	payload = NULL;
	fprintf(stderr, "[%s] hello ok ua=%s nk=%08x generation=%s%s\n",
		peer_s, hello.user_agent, hello.nk,
		hello.generation == PRIME_GEN_V3 ? "v3" : "v1",
		public_stratum ? " stratum-v1" : "");

	if (prime_accept(&hello, pool, motd, &resp, &resp_len, &session) != 0) {
		fprintf(stderr, "[%s] could not build handshake response\n", peer_s);
		prime_conn_mining_free(&mining);
		return;
	}
	if (write_all(fd, resp, resp_len) != 0) {
		fprintf(stderr, "[%s] handshake write failed\n", peer_s);
		free(resp);
		prime_conn_mining_free(&mining);
		return;
	}
	free(resp);
	fprintf(stderr, "[%s] handshake response sent (%zu bytes)\n", peer_s, resp_len);

	prime_new_resume_token(opt->prime_id, token);
	if (hello.generation == PRIME_GEN_V3) {
		if (prime_encode_config_v3(opt, token, &cfg, &cfg_len) != 0) {
			fprintf(stderr, "[%s] v3 config encode failed\n", peer_s);
			prime_conn_mining_free(&mining);
			return;
		}
	} else if (prime_encode_config_v1(opt, &cfg, &cfg_len) != 0) {
		fprintf(stderr, "[%s] v1 config encode failed\n", peer_s);
		prime_conn_mining_free(&mining);
		return;
	}
	if (prime_session_encrypt(&session, PRIME_CMD_MINING, cfg, cfg_len, true, &cfg_wire, &cfg_wire_len) != 0) {
		fprintf(stderr, "[%s] config encrypt failed\n", peer_s);
		free(cfg);
		prime_conn_mining_free(&mining);
		return;
	}
	free(cfg);
	if (write_all(fd, cfg_wire, cfg_wire_len) != 0) {
		fprintf(stderr, "[%s] config write failed\n", peer_s);
		free(cfg_wire);
		prime_conn_mining_free(&mining);
		return;
	}
	free(cfg_wire);
	fprintf(stderr, "[%s] sent %s 0x99 config (%zu bytes, signed, abw_disabled=%d)\n",
		peer_s, hello.generation == PRIME_GEN_V3 ? "v3" : "v1", cfg_wire_len,
		opt->abw_disabled ? 1 : 0);
	prime_stats_client_open();
	counted_client = 1;

	if (hello.generation == PRIME_GEN_V3 && !opt->abw_disabled) {
		int resumed = 0;
		if (hello.resume_present && opt->pool
		    && prime_pool_resume_get(opt->pool, hello.resume_token, hello.client_sign_pk,
					     &mining.next_coinbaser_id, &mining.abw)) {
			prime_abw_resumed(&mining.abw);
			memcpy(token, hello.resume_token, PRIME_RESUME_TOKEN_LEN);
			resumed = 1;
			fprintf(stderr, "[%s] resume accepted\n", peer_s);
		} else {
			prime_abw_start(&mining.abw, opt->abw_reveal_after_sec);
		}
		mining.abw_on = 1;
		{
			unsigned char **notices = NULL;
			size_t *nlens = NULL, nn = 0, k;
			prime_abw_encode_notices(&mining.abw, &notices, &nlens, &nn);
			for (k = 0; k < nn; k++) {
				unsigned char *nw = NULL;
				size_t nwl = 0;
				if (prime_session_encrypt(&session, PRIME_CMD_MINING, notices[k],
							  nlens[k], false, &nw, &nwl) == 0 && nw) {
					if (write_all(fd, nw, nwl) != 0) {
						free(nw);
						free(notices[k]);
						break;
					}
					free(nw);
				}
				free(notices[k]);
			}
			free(notices);
			free(nlens);
			fprintf(stderr, "[%s] sent %zu ABW notice(s)%s\n", peer_s, nn,
				resumed ? " (resume)" : "");
		}
	}

	{
		struct timeval tv;
		tv.tv_sec = 2;
		tv.tv_usec = 0;
		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
	}

	while (!g_stop) {
		unsigned char *plain = NULL;
		size_t plain_len = 0;
		if (read_exact(fd, hdr_bytes, 4) != 0) {
			/* Timeout only: SO_RCVTIMEO so g_stop can be noticed.
			 * read_exact already retries EINTR. EOF is ECONNRESET. */
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				continue;
			}
			fprintf(stderr, "[%s] disconnected\n", peer_s);
			break;
		}
		prime_ratchet_unmask(&session.rx_headers, hdr_bytes, &header);
		if (header.cmd_len > PRIME_MAX_CMD_LEN) {
			fprintf(stderr, "[%s] frame too large\n", peer_s);
			break;
		}
		payload = malloc(header.cmd_len ? header.cmd_len : 1);
		if (!payload || (header.cmd_len && read_exact(fd, payload, header.cmd_len) != 0)) {
			fprintf(stderr, "[%s] frame body failed\n", peer_s);
			free(payload);
			break;
		}
		if (header.is_encrypted_channel) {
			if (prime_session_decrypt(&session, &header, payload, header.cmd_len, &plain, &plain_len) != 0) {
				fprintf(stderr, "[%s] decrypt failed cmd=%u len=%u\n",
					peer_s, header.proto_cmd, header.cmd_len);
				free(payload);
				break;
			}
			if (header.proto_cmd == PRIME_CMD_BULK) {
				int done = 0;
				unsigned char ack[12], *aw = NULL;
				size_t awl = 0;
				if (prime_bulk_ingest(&bulk, &bulk_len, &bulk_cap, &bid, &btot, &bgot,
						      plain, plain_len, &done) == 0) {
					prime_bulk_ack(bid, bgot, ack);
					if (prime_session_encrypt(&session, PRIME_CMD_BULK, ack, 12,
								  false, &aw, &awl) == 0 && aw) {
						write_all(fd, aw, awl);
						free(aw);
					}
					if (done && bulk) {
						unsigned char *reply = NULL;
						size_t reply_len = 0;
						prime_handle_mining(&session, &mining, opt, bulk,
								    bulk_len, &reply, &reply_len,
								    peer_s);
						if (reply) {
							write_all(fd, reply, reply_len);
							free(reply);
						}
						free(bulk);
						bulk = NULL;
						bulk_len = bulk_cap = 0;
						bid = btot = bgot = 0;
					}
				}
			} else if (header.proto_cmd == PRIME_CMD_MINING) {
				unsigned char *reply = NULL;
				size_t reply_len = 0;
				if (!logged_first_mining && plain_len) {
					logged_first_mining = 1;
					fprintf(stderr, "[%s] first mining frame sub=%02x len=%zu\n",
						peer_s, plain[0], plain_len);
				}
				if (prime_handle_mining(&session, &mining, opt, plain, plain_len,
							&reply, &reply_len, peer_s) != 0) {
					fprintf(stderr, "[%s] mining handler failed\n", peer_s);
				} else if (reply) {
					if (write_all(fd, reply, reply_len) != 0) {
						fprintf(stderr, "[%s] mining reply write failed\n", peer_s);
						free(reply);
						free(plain);
						free(payload);
						break;
					}
					free(reply);
				}
			} else {
				fprintf(stderr, "[%s] frame cmd=%u sub=%02x len=%zu\n",
					peer_s, header.proto_cmd, plain_len ? plain[0] : 0, plain_len);
			}
			free(plain);
		} else {
			fprintf(stderr, "[%s] unencrypted frame cmd=%u len=%u\n",
				peer_s, header.proto_cmd, header.cmd_len);
		}
		free(payload);
		payload = NULL;
	}
	if (opt->pool && hello.generation == PRIME_GEN_V3) {
		prime_pool_resume_put(opt->pool, token, hello.client_sign_pk,
				      mining.next_coinbaser_id, mining.abw_on ? &mining.abw : NULL);
	}
	if (counted_client) {
		prime_stats_client_close();
	}
	free(bulk);
	prime_conn_mining_free(&mining);
}

typedef struct {
	int fd;
	struct sockaddr_in peer;
	const prime_keypairs *pool;
	const char *motd;
	const prime_config_opts *opt;
	int public_stratum;
} prime_client_arg;

static void *client_thread(void *arg)
{
	prime_client_arg *a = arg;
	handle_client(a->fd, &a->peer, a->pool, a->motd, a->opt, a->public_stratum);
	close(a->fd);
	free(a);
	return NULL;
}

static int listen_inet(const char *host, uint16_t port)
{
	int sock, on = 1;
	struct sockaddr_in addr;

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("socket");
		return -1;
	}
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
	memset(&addr, 0, sizeof addr);
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
		fprintf(stderr, "listen host must be an IPv4 address (got %s)\n", host);
		close(sock);
		return -1;
	}
	if (bind(sock, (struct sockaddr *)&addr, sizeof addr) != 0) {
		perror("bind");
		close(sock);
		return -1;
	}
	if (listen(sock, 16) != 0) {
		perror("listen");
		close(sock);
		return -1;
	}
	return sock;
}

static void spawn_client(int fd, const struct sockaddr_in *peer, const prime_keypairs *pool,
			 const char *motd, const prime_config_opts *opt, int public_stratum)
{
	pthread_t th;
	prime_client_arg *arg = malloc(sizeof *arg);
	if (!arg) {
		close(fd);
		return;
	}
	arg->fd = fd;
	arg->peer = *peer;
	arg->pool = pool;
	arg->motd = motd;
	arg->opt = opt;
	arg->public_stratum = public_stratum;
	if (pthread_create(&th, NULL, client_thread, arg) != 0) {
		close(fd);
		free(arg);
		return;
	}
	pthread_detach(th);
}

static void usage(const char *argv0)
{
	fprintf(stderr,
		"Usage: %s [--self-test] [--listen HOST:PORT] [--keys PATH]\n"
		"          [--motd TEXT] [--tag TEXT] [--min-diff N] [--payout-script HEX]\n"
		"          [--prime-id N] [--source-listen HOST:PORT] [--source-url URL]\n"
		"          [--bitcoin-datadir PATH] [--block-dir PATH] [--ledger PATH]\n"
		"          [--stats-listen HOST:PORT] [--stratum-listen HOST:PORT]\n"
		"          [--sv1-api URL]\n"
		"          [--fee-bps N] [--fee-after-first-block]\n"
		"          [--min-payout N]\n"
		"          [--window N] [--window-floor N] [--abw-disabled] [--abw-reveal-after N]\n"
		"          [--no-require-split] [--no-bulk]\n"
		"          [--dump-ledger] [--settle-block HASH|list] [--void-block HASH]\n"
		"          [--empty-block HASH|list] [--settle-empty HASH] [--void-empty HASH]\n"
		"Default listen is 127.0.0.1:28915. Do not bind a public address until\n"
		"you intend to offer source (AGPL section 13).\n",
		argv0);
}

int main(int argc, char **argv)
{
	const char *listen_addr = "127.0.0.1:28915";
	const char *keys_path = NULL;
	const char *motd = "c_datum_prime (C) AGPL-3.0-or-later. Source: https://github.com/Blockvase/c_datum_prime";
	const char *tag = "Blockvase";
	const char *payout_hex = "0014548ba41399d57523d5e14d5082b98859d19dfc99";
	const char *source_listen = "0.0.0.0:28916";
	const char *source_url = "http://pool.blockvase.com:28916/";
	const char *bitcoin_datadir = NULL;
	const char *block_dir = NULL;
	const char *ledger_path = NULL;
	const char *stats_listen = "0.0.0.0:28917";
	const char *stratum_listen = NULL;
	const char *sv1_api = "http://127.0.0.1:7153";
	uint64_t min_diff = 65536;
	uint64_t prime_id = 1;
	uint64_t min_payout = 546;
	uint64_t window_floor = 1;
	double window_multiple = 8.0;
	uint16_t fee_bps = 0;
	int fee_after_first = 0;
	unsigned abw_reveal = 300;
	int abw_disabled = 0;
	int require_split = 1;
	int bulk_framing = 1;
	int do_selftest = 0;
	int dump_ledger = 0;
	const char *settle_arg = NULL;
	const char *void_arg = NULL;
	const char *empty_arg = NULL;
	const char *settle_empty_arg = NULL;
	const char *void_empty_arg = NULL;
	int i;
	char host[128];
	char bitcoin_home[512];
	char data_dir[512];
	char keys_buf[600];
	char ledger_buf[600];
	char blocks_buf[600];
	uint16_t port = 28915;
	prime_keypairs pool;
	char pubkey[129];
	unsigned char payout[PRIME_MAX_PAYOUT_SCRIPT];
	size_t payout_len = 0;
	prime_config_opts opt;
	int sock;
	int sock_sv1 = -1;

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--self-test") == 0) {
			do_selftest = 1;
		} else if (strcmp(argv[i], "--listen") == 0 && i + 1 < argc) {
			listen_addr = argv[++i];
		} else if (strcmp(argv[i], "--keys") == 0 && i + 1 < argc) {
			keys_path = argv[++i];
		} else if (strcmp(argv[i], "--motd") == 0 && i + 1 < argc) {
			motd = argv[++i];
		} else if (strcmp(argv[i], "--tag") == 0 && i + 1 < argc) {
			tag = argv[++i];
		} else if (strcmp(argv[i], "--min-diff") == 0 && i + 1 < argc) {
			min_diff = strtoull(argv[++i], NULL, 10);
		} else if (strcmp(argv[i], "--prime-id") == 0 && i + 1 < argc) {
			prime_id = strtoull(argv[++i], NULL, 10);
		} else if (strcmp(argv[i], "--payout-script") == 0 && i + 1 < argc) {
			payout_hex = argv[++i];
		} else if (strcmp(argv[i], "--source-listen") == 0 && i + 1 < argc) {
			source_listen = argv[++i];
		} else if (strcmp(argv[i], "--source-url") == 0 && i + 1 < argc) {
			source_url = argv[++i];
		} else if (strcmp(argv[i], "--bitcoin-datadir") == 0 && i + 1 < argc) {
			bitcoin_datadir = argv[++i];
		} else if (strcmp(argv[i], "--block-dir") == 0 && i + 1 < argc) {
			block_dir = argv[++i];
		} else if (strcmp(argv[i], "--ledger") == 0 && i + 1 < argc) {
			ledger_path = argv[++i];
		} else if (strcmp(argv[i], "--stats-listen") == 0 && i + 1 < argc) {
			stats_listen = argv[++i];
		} else if (strcmp(argv[i], "--stratum-listen") == 0 && i + 1 < argc) {
			stratum_listen = argv[++i];
		} else if (strcmp(argv[i], "--sv1-api") == 0 && i + 1 < argc) {
			sv1_api = argv[++i];
		} else if (strcmp(argv[i], "--fee-bps") == 0 && i + 1 < argc) {
			fee_bps = (uint16_t)strtoul(argv[++i], NULL, 10);
		} else if (strcmp(argv[i], "--fee-after-first-block") == 0) {
			fee_after_first = 1;
		} else if (strcmp(argv[i], "--min-payout") == 0 && i + 1 < argc) {
			min_payout = strtoull(argv[++i], NULL, 10);
		} else if (strcmp(argv[i], "--window") == 0 && i + 1 < argc) {
			window_multiple = strtod(argv[++i], NULL);
		} else if (strcmp(argv[i], "--window-floor") == 0 && i + 1 < argc) {
			window_floor = strtoull(argv[++i], NULL, 10);
		} else if (strcmp(argv[i], "--abw-reveal-after") == 0 && i + 1 < argc) {
			abw_reveal = (unsigned)strtoul(argv[++i], NULL, 10);
		} else if (strcmp(argv[i], "--abw-disabled") == 0) {
			abw_disabled = 1;
		} else if (strcmp(argv[i], "--no-require-split") == 0) {
			require_split = 0;
		} else if (strcmp(argv[i], "--no-bulk") == 0) {
			bulk_framing = 0;
		} else if (strcmp(argv[i], "--dump-ledger") == 0) {
			dump_ledger = 1;
		} else if (strcmp(argv[i], "--settle-block") == 0 && i + 1 < argc) {
			settle_arg = argv[++i];
		} else if (strcmp(argv[i], "--void-block") == 0 && i + 1 < argc) {
			void_arg = argv[++i];
		} else if (strcmp(argv[i], "--empty-block") == 0 && i + 1 < argc) {
			empty_arg = argv[++i];
		} else if (strcmp(argv[i], "--settle-empty") == 0 && i + 1 < argc) {
			settle_empty_arg = argv[++i];
		} else if (strcmp(argv[i], "--void-empty") == 0 && i + 1 < argc) {
			void_empty_arg = argv[++i];
		} else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
			usage(argv[0]);
			return 0;
		} else {
			usage(argv[0]);
			return 2;
		}
	}

	if (do_selftest) {
		return prime_selftest();
	}

	tree_data_dir(data_dir, sizeof data_dir);
	if (!keys_path || !keys_path[0]) {
		snprintf(keys_buf, sizeof keys_buf, "%s/pool.keys", data_dir);
		keys_path = keys_buf;
	}
	if (!ledger_path || !ledger_path[0]) {
		snprintf(ledger_buf, sizeof ledger_buf, "%s/ledger", data_dir);
		ledger_path = ledger_buf;
	}
	if (!block_dir || !block_dir[0]) {
		snprintf(blocks_buf, sizeof blocks_buf, "%s/blocks", data_dir);
		block_dir = blocks_buf;
	}

	if (!bitcoin_datadir || !bitcoin_datadir[0]) {
		const char *home = getenv("HOME");
		if (home && home[0]) {
			snprintf(bitcoin_home, sizeof bitcoin_home, "%s/.bitcoin", home);
			bitcoin_datadir = bitcoin_home;
		} else {
			bitcoin_datadir = "";
		}
	}

	if (sodium_init() < 0) {
		fprintf(stderr, "sodium_init failed\n");
		return 1;
	}
	if (parse_listen(listen_addr, host, sizeof host, &port) != 0) {
		fprintf(stderr, "bad --listen %s\n", listen_addr);
		return 2;
	}
	if (parse_hex_script(payout_hex, payout, &payout_len, sizeof payout) != 0) {
		fprintf(stderr, "bad --payout-script\n");
		return 2;
	}
	if (prime_keys_load_or_create(keys_path, &pool) != 0) {
		fprintf(stderr, "could not load or create keys at %s: %s\n", keys_path, strerror(errno));
		return 1;
	}
	prime_keys_pubkey_hex(&pool, pubkey);
	memset(&opt, 0, sizeof opt);
	opt.payout_script = payout;
	opt.payout_script_len = payout_len;
	opt.prime_id = prime_id;
	opt.coinbase_tag = tag;
	opt.min_difficulty = min_diff;
	opt.abw_disabled = abw_disabled ? true : false;
	opt.require_split = require_split ? true : false;
	opt.bulk_framing = bulk_framing ? true : false;
	opt.fee_bps = fee_bps;
	opt.fee_after_first_block = fee_after_first ? true : false;
	opt.min_payout = min_payout;
	opt.window_multiple = window_multiple;
	opt.window_floor = window_floor;
	opt.abw_reveal_after_sec = abw_reveal;
	opt.bitcoin_datadir = bitcoin_datadir[0] ? bitcoin_datadir : NULL;
	opt.block_dir = block_dir[0] ? block_dir : NULL;
	opt.ledger_path = ledger_path;
	opt.stats_listen = stats_listen;
	opt.stratum_listen = stratum_listen;
	opt.sv1_api = sv1_api;
	opt.pool = prime_pool_open(ledger_path, 0, min_payout,
				   fee_after_first ? 0 : fee_bps);
	if (!opt.pool) {
		fprintf(stderr, "could not open ledger %s\n", ledger_path);
		return 1;
	}
	if (fee_after_first) {
		if (!fee_bps) {
			fprintf(stderr, "warning: --fee-after-first-block with --fee-bps 0 does nothing\n");
		}
		prime_pool_set_fee_after_first_block(opt.pool, fee_bps);
		if (prime_pool_blocks_found(opt.pool)) {
			fprintf(stderr,
				"fee: %u bps (%.2f%%); ledger already has %llu block(s)\n",
				(unsigned)prime_pool_fee_bps(opt.pool),
				(double)prime_pool_fee_bps(opt.pool) / 100.0,
				(unsigned long long)prime_pool_blocks_found(opt.pool));
		} else {
			fprintf(stderr, "fee: 0 until first pool block, then %u bps (%.2f%%)\n",
				(unsigned)fee_bps, (double)fee_bps / 100.0);
		}
	} else {
		fprintf(stderr, "fee: %u bps (%.2f%%)\n", (unsigned)fee_bps,
			(double)fee_bps / 100.0);
	}
	if (dump_ledger) {
		prime_pool_dump(opt.pool, stdout);
		prime_pool_close(opt.pool);
		return 0;
	}
	if (settle_arg) {
		int rc = 0;
		if (strcmp(settle_arg, "list") == 0) {
			prime_pool_list_owed(opt.pool, stdout);
		} else {
			unsigned char hash[32];
			if (prime_hex_decode(settle_arg, hash, 32) != 0) {
				fprintf(stderr, "--settle-block takes 64 hex digits or list\n");
				rc = 2;
			} else if (prime_pool_settle(opt.pool, hash, (uint64_t)time(NULL)) != 0) {
				fprintf(stderr, "no owed block under %s; --settle-block list prints them\n",
					settle_arg);
				rc = 2;
			}
		}
		prime_pool_close(opt.pool);
		return rc;
	}
	if (void_arg) {
		unsigned char hash[32];
		int rc = 0;
		if (prime_hex_decode(void_arg, hash, 32) != 0) {
			fprintf(stderr, "--void-block takes 64 hex digits\n");
			rc = 2;
		} else if (prime_pool_void_owed(opt.pool, hash) != 0) {
			fprintf(stderr, "no owed block under %s\n", void_arg);
			rc = 2;
		}
		prime_pool_close(opt.pool);
		return rc;
	}
	if (empty_arg) {
		int rc = 0;
		if (strcmp(empty_arg, "list") == 0) {
			prime_pool_list_empty(opt.pool, stdout);
		} else {
			unsigned char hash[32];
			if (prime_hex_decode(empty_arg, hash, 32) != 0) {
				fprintf(stderr, "--empty-block takes 64 hex digits or list\n");
				rc = 2;
			} else if (prime_pool_empty_sendmany(opt.pool, hash, stdout) != 0) {
				fprintf(stderr, "no empty find under %s; --empty-block list prints them\n",
					empty_arg);
				rc = 2;
			}
		}
		prime_pool_close(opt.pool);
		return rc;
	}
	if (settle_empty_arg) {
		unsigned char hash[32];
		int rc = 0;
		if (prime_hex_decode(settle_empty_arg, hash, 32) != 0) {
			fprintf(stderr, "--settle-empty takes 64 hex digits\n");
			rc = 2;
		} else if (prime_pool_settle_empty(opt.pool, hash, (uint64_t)time(NULL)) != 0) {
			fprintf(stderr, "no empty find under %s\n", settle_empty_arg);
			rc = 2;
		}
		prime_pool_close(opt.pool);
		return rc;
	}
	if (void_empty_arg) {
		unsigned char hash[32];
		int rc = 0;
		if (prime_hex_decode(void_empty_arg, hash, 32) != 0) {
			fprintf(stderr, "--void-empty takes 64 hex digits\n");
			rc = 2;
		} else if (prime_pool_void_empty(opt.pool, hash) != 0) {
			fprintf(stderr, "no empty find under %s\n", void_empty_arg);
			rc = 2;
		}
		prime_pool_close(opt.pool);
		return rc;
	}
	if (bitcoin_datadir && bitcoin_datadir[0]) {
		prime_tip_start(bitcoin_datadir, opt.pool, window_multiple, window_floor);
	}
	if (prime_cap_start(bitcoin_datadir, opt.pool, sv1_api) != 0) {
		fprintf(stderr, "warning: 120-block SV1 cap thread did not start\n");
	}

	if (prime_source_start(source_listen, source_url) != 0) {
		fprintf(stderr, "warning: AGPL source HTTP did not start on %s\n", source_listen);
	}
	if (stats_listen && stats_listen[0]
	    && prime_stats_start(stats_listen, opt.pool, motd, pubkey, &opt, host, port,
				 source_url) != 0) {
		fprintf(stderr, "warning: stats HTTP did not start on %s\n", stats_listen);
	}

	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);
	signal(SIGPIPE, SIG_IGN);

	sock = listen_inet(host, port);
	if (sock < 0) {
		return 1;
	}

	fprintf(stderr, "c-datum-prime listening on %s:%u\n", host, port);
	if (stratum_listen && stratum_listen[0]) {
		char sv_host[128];
		uint16_t sv_port = 0;
		if (parse_listen(stratum_listen, sv_host, sizeof sv_host, &sv_port) != 0) {
			fprintf(stderr, "bad --stratum-listen %s\n", stratum_listen);
			close(sock);
			return 1;
		}
		sock_sv1 = listen_inet(sv_host, sv_port);
		if (sock_sv1 < 0) {
			close(sock);
			return 1;
		}
		fprintf(stderr, "c-datum-prime stratum-v1 DATUM listen %s:%u (2.3%% / 2%% rebate)\n",
			sv_host, sv_port);
	}
	fprintf(stderr, "pool_pubkey=%s\n", pubkey);
	fprintf(stderr, "keys=%s tag=%s min_diff=%llu prime_id=%llu abw=%s split=%s\n",
		keys_path, tag, (unsigned long long)min_diff, (unsigned long long)prime_id,
		abw_disabled ? "off" : "on", require_split ? "require" : "off");
	fprintf(stderr, "translated from RATUM Prime by iohzrd; AGPL-3.0-or-later\n");

	while (!g_stop) {
		fd_set rfds;
		struct timeval tv;
		int maxfd = sock;
		FD_ZERO(&rfds);
		FD_SET(sock, &rfds);
		if (sock_sv1 >= 0) {
			FD_SET(sock_sv1, &rfds);
			if (sock_sv1 > maxfd) {
				maxfd = sock_sv1;
			}
		}
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		if (select(maxfd + 1, &rfds, NULL, NULL, &tv) < 0) {
			if (errno == EINTR) {
				continue;
			}
			perror("select");
			break;
		}
		if (FD_ISSET(sock, &rfds)) {
			struct sockaddr_in peer;
			socklen_t plen = sizeof peer;
			int c = accept(sock, (struct sockaddr *)&peer, &plen);
			if (c >= 0) {
				spawn_client(c, &peer, &pool, motd, &opt, 0);
			} else if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
				perror("accept");
				break;
			}
		}
		if (sock_sv1 >= 0 && FD_ISSET(sock_sv1, &rfds)) {
			struct sockaddr_in peer;
			socklen_t plen = sizeof peer;
			int c = accept(sock_sv1, (struct sockaddr *)&peer, &plen);
			if (c >= 0) {
				spawn_client(c, &peer, &pool, motd, &opt, 1);
			} else if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
				perror("accept");
				break;
			}
		}
	}
	close(sock);
	if (sock_sv1 >= 0) {
		close(sock_sv1);
	}
	prime_pool_close(opt.pool);
	return 0;
}
