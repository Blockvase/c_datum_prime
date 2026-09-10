/* Public pool stats. Translated in spirit from RATUM prime/src/stats.rs.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static prime_pool *g_pool;
static char g_motd[256];
static char g_pubkey[129];
static char g_source_url[256];
static char g_datum_host[128];
static uint16_t g_datum_port;
static uint16_t g_fee_bps;
static int g_fee_after_first;
static uint64_t g_min_payout;
static double g_window_multiple;
static uint64_t g_window_floor;
static uint64_t g_min_diff;
static int g_abw_enabled;
static int g_require_split;
static uint16_t g_sv1_port;
static pthread_mutex_t g_client_mu = PTHREAD_MUTEX_INITIALIZER;
static unsigned g_clients;

static void copy_url_host(const char *url, char *out, size_t out_len)
{
	const char *s, *e;
	size_t n;
	if (!out || !out_len) {
		return;
	}
	snprintf(out, out_len, "pool.blockvase.com");
	if (!url || !url[0]) {
		return;
	}
	s = strstr(url, "://");
	s = s ? s + 3 : url;
	e = s;
	while (*e && *e != ':' && *e != '/') {
		e++;
	}
	n = (size_t)(e - s);
	if (n && n < out_len) {
		memcpy(out, s, n);
		out[n] = 0;
	}
}

static unsigned connected_clients(void)
{
	unsigned n;
	pthread_mutex_lock(&g_client_mu);
	n = g_clients;
	pthread_mutex_unlock(&g_client_mu);
	return n;
}

void prime_stats_client_open(void)
{
	pthread_mutex_lock(&g_client_mu);
	g_clients++;
	pthread_mutex_unlock(&g_client_mu);
}

void prime_stats_client_close(void)
{
	pthread_mutex_lock(&g_client_mu);
	if (g_clients) {
		g_clients--;
	}
	pthread_mutex_unlock(&g_client_mu);
}

static int write_all(int fd, const void *buf, size_t n);

static void parse_shares_query(const char *req, unsigned char after[32], int *have_after,
			       size_t *limit)
{
	const char *q, *a, *l;
	char hex[65];
	size_t n;

	*have_after = 0;
	*limit = 500;
	if (!req) {
		return;
	}
	q = strchr(req, '?');
	if (!q || q > req + 256) {
		return;
	}
	a = strstr(q, "after=");
	if (a) {
		a += 6;
		n = 0;
		while (n < 64 && a[n] && a[n] != '&' && a[n] != ' ' && a[n] != '\r') {
			hex[n] = a[n];
			n++;
		}
		hex[n] = 0;
		if (n == 64 && prime_hex_decode(hex, after, 32) == 0) {
			*have_after = 1;
		}
	}
	l = strstr(q, "limit=");
	if (l) {
		unsigned long v = strtoul(l + 6, NULL, 10);
		if (v) {
			*limit = (size_t)v;
		}
	}
}

static void send_json(int fd, const char *json)
{
	char hdr[256];
	size_t n = strlen(json);

	snprintf(hdr, sizeof hdr,
		 "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
		 "Access-Control-Allow-Origin: *\r\n"
		 "Content-Length: %zu\r\nConnection: close\r\n\r\n",
		 n);
	write_all(fd, hdr, strlen(hdr));
	write_all(fd, json, n);
}

static int write_all(int fd, const void *buf, size_t n)
{
	const unsigned char *p = buf;
	size_t off = 0;
	while (off < n) {
		ssize_t w = send(fd, p + off, n - off, MSG_NOSIGNAL);
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

static int miners_array_from_stats(const char *stats, char *out, size_t out_len)
{
	const char *m, *p;
	int in_string = 0, esc = 0, depth = 0;
	size_t n;
	if (!out || !out_len) {
		return -1;
	}
	snprintf(out, out_len, "[]");
	m = strstr(stats ? stats : "", "\"miners\":");
	if (!m) {
		return 0;
	}
	p = strchr(m, '[');
	if (!p) {
		return 0;
	}
	for (m = p; *p; p++) {
		if (esc) {
			esc = 0;
		} else if (*p == '\\' && in_string) {
			esc = 1;
		} else if (*p == '"') {
			in_string = !in_string;
		} else if (!in_string && *p == '[') {
			depth++;
		} else if (!in_string && *p == ']') {
			depth--;
			if (depth == 0) {
				p++;
				break;
			}
		}
	}
	n = (size_t)(p - m);
	if (n == 0 || n >= out_len) {
		return -1;
	}
	memcpy(out, m, n);
	out[n] = 0;
	return 0;
}

static int build_pool_json(char *out, size_t out_len, const char *stats)
{
	char miners[12288];
	uint64_t shares = prime_pool_share_count(g_pool);
	uint64_t work = prime_pool_total_work(g_pool);
	uint64_t window = prime_pool_window(g_pool);
	uint64_t blocks = prime_pool_blocks_found(g_pool);
	uint16_t fee_bps = g_pool ? prime_pool_fee_bps(g_pool) : g_fee_bps;
	double progress = window ? ((double)work * 100.0 / (double)window) : 0.0;
	unsigned clients = connected_clients();

	if (miners_array_from_stats(stats, miners, sizeof miners) != 0) {
		snprintf(miners, sizeof miners, "[]");
	}
	char nethash[768];
	if (progress > 100.0) {
		progress = 100.0;
	}
	if (prime_nethash_json(nethash, sizeof nethash) < 0) {
		snprintf(nethash, sizeof nethash, "{}");
	}
	return snprintf(out, out_len,
			"{\"schema_version\":1,"
			"\"available\":true,"
			"\"updated_at\":%llu,"
			"\"pool\":{"
			"\"name\":\"c_datum_prime\","
			"\"style\":\"Non-custodial DATUM pooled mining with a rolling 8-block share-window coinbase split\","
			"\"fee_bps\":%u,"
			"\"fee_percent\":%.4f,"
			"\"datum_host\":\"%s\","
			"\"datum_port\":%u,"
			"\"source_url\":\"%s\","
			"\"pool_pubkey\":\"%s\","
			"\"payout_address_types\":[\"p2pkh\",\"p2sh\",\"p2wpkh\",\"p2wsh\",\"p2tr\"],"
			"\"max_split_outputs\":%u,"
			"\"min_payout_sats\":%llu,"
			"\"stratum_v1_datum_listen_port\":%u,"
			"\"stratum_v1_port\":%u,"
			"\"stratum_v1_host\":\"%s\","
			"\"stratum_v1_url\":\"stratum+tcp://%s:%u\","
			"\"stratum_v1_username\":\"Bitcoin address, optional .worker\","
			"\"stratum_v1_password\":\"x\","
			"\"stratum_v1_pow\":\"blake2b\","
			"\"stratum_v1_fee_bps\":%u,"
			"\"stratum_v1_fee_percent\":%.4f,"
			"\"stratum_v1_datum_rebate_bps\":%u,"
			"\"stratum_v1_operator_bps\":%u,"
			"\"stratum_v1_miner_keep_percent\":%.4f,"
			"\"fee_until_first_block_bps\":0,"
			"\"fee_after_first_block\":%s,"
			"\"fee_after_first_block_bps\":%u"
			"},"
			"\"status\":{"
			"\"connected_datum_clients\":%u,"
			"\"min_difficulty\":%llu,"
			"\"shares\":%llu,"
			"\"work\":%llu,"
			"\"window\":%llu,"
			"\"window_progress_percent\":%.6f,"
			"\"blocks_found\":%llu,"
			"\"hashrate_hs\":%.8g,"
			"\"hashrate_window_sec\":%u,"
			"\"abw_enabled\":%s,"
			"\"require_split\":%s"
			"},"
			"\"window\":{"
			"\"type\":\"work\","
			"\"multiple\":%.8g,"
			"\"floor\":%llu,"
			"\"description\":\"8x network difficulty, rolling by accepted share work\","
			"\"current_work\":%llu,"
			"\"target_work\":%llu"
			"},"
			"\"nethash\":%s,"
			"\"miners\":%s,"
			"\"links\":{"
			"\"datum_endpoint\":\"%s:%u\","
			"\"stratum_v1\":\"stratum+tcp://%s:%u\","
			"\"source\":\"%s\","
			"\"shares\":\"/shares.json\""
			"}"
			"}",
			(unsigned long long)time(NULL), (unsigned)fee_bps,
			(double)fee_bps / 100.0, g_datum_host, (unsigned)g_datum_port,
			g_source_url, g_pubkey, (unsigned)PRIME_MAX_SPLIT_OUTPUTS,
			(unsigned long long)g_min_payout, (unsigned)g_sv1_port,
			(unsigned)PRIME_SV1_PUBLIC_STRATUM_PORT, g_datum_host, g_datum_host,
			(unsigned)PRIME_SV1_PUBLIC_STRATUM_PORT,
			(unsigned)PRIME_SV1_FEE_BPS, (double)PRIME_SV1_FEE_BPS / 100.0,
			(unsigned)PRIME_SV1_DATUM_REBATE_BPS, (unsigned)PRIME_SV1_OPERATOR_BPS,
			100.0 - (double)PRIME_SV1_FEE_BPS / 100.0,
			g_fee_after_first ? "true" : "false",
			(unsigned)(g_fee_after_first ? g_fee_bps : fee_bps), clients,
			(unsigned long long)g_min_diff, (unsigned long long)shares,
			(unsigned long long)work, (unsigned long long)window, progress,
			(unsigned long long)blocks, prime_pool_hashrate_hs(g_pool),
			(unsigned)PRIME_HASHRATE_WINDOW_SEC,
			g_abw_enabled ? "true" : "false",
			g_require_split ? "true" : "false", g_window_multiple,
			(unsigned long long)g_window_floor, (unsigned long long)work,
			(unsigned long long)window, nethash, miners, g_datum_host, (unsigned)g_datum_port,
			g_datum_host, (unsigned)PRIME_SV1_PUBLIC_STRATUM_PORT, g_source_url);
}

static void *stats_thread(void *arg)
{
	int fd = (int)(intptr_t)arg;
	for (;;) {
		int c = accept(fd, NULL, NULL);
		char req[512];
		char json[16384];
		char pool_json[24576];
		char body[32768];
		char hdr[256];
		ssize_t n;
		int want_json = 0;
		int want_pool = 0;
		int want_shares = 0;
		if (c < 0) {
			if (errno == EINTR) {
				continue;
			}
			break;
		}
		n = recv(c, req, sizeof req - 1, 0);
		if (n > 0) {
			req[n] = 0;
			want_shares = strstr(req, "GET /shares.json") || strstr(req, "GET /tides.json")
				|| strstr(req, "GET /api/shares");
			want_json = !want_shares && (strstr(req, "GET /stats.json")
				|| strstr(req, "GET /api"));
			want_pool = strstr(req, "GET /pool.json") || strstr(req, "GET /api/pool")
				|| strstr(req, "GET /datum_pool");
		}
		if (want_shares) {
			unsigned char after[32];
			int have_after = 0;
			size_t limit = 500;
			char *shares = malloc(600000);
			if (!shares) {
				send_json(c, "{\"schema_version\":1,\"available\":false}\n");
				close(c);
				continue;
			}
			parse_shares_query(req, after, &have_after, &limit);
			if (prime_pool_shares_json(g_pool, shares, 600000,
						   have_after ? after : NULL, limit) != 0) {
				snprintf(shares, 600000,
					 "{\"schema_version\":1,\"available\":false}\n");
			}
			send_json(c, shares);
			free(shares);
			close(c);
			continue;
		}
		if (prime_pool_stats_json(g_pool, json, sizeof json) != 0) {
			snprintf(json, sizeof json, "{\"shares\":0}");
		}
		if (want_pool) {
			int pw = build_pool_json(pool_json, sizeof pool_json, json);
			if (pw < 0 || (size_t)pw >= sizeof pool_json) {
				snprintf(pool_json, sizeof pool_json,
					 "{\"schema_version\":1,\"available\":false}");
			}
			snprintf(body, sizeof body, "%s\n", pool_json);
			snprintf(hdr, sizeof hdr,
				 "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
				 "Content-Length: %zu\r\nConnection: close\r\n\r\n",
				 strlen(body));
		} else if (want_json) {
			snprintf(body, sizeof body, "%s\n", json);
			snprintf(hdr, sizeof hdr,
				 "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
				 "Content-Length: %zu\r\nConnection: close\r\n\r\n",
				 strlen(body));
		} else {
			snprintf(body, sizeof body,
				 "<!doctype html><html><head><meta charset=utf-8>"
				 "<title>c_datum_prime</title></head><body>"
				 "<h1>c_datum_prime</h1>"
				 "<p>%s</p>"
				 "<p>pool_pubkey <code>%.64s...</code></p>"
				 "<p><a href=\"/pool.json\">Pool JSON</a> · "
				 "<a href=\"/shares.json\">Share log</a></p>"
				 "<pre>%s</pre>"
				 "<p>Source: <a href=\"http://pool.blockvase.com:28916/\">AGPL</a> "
				 "translated from RATUM Prime by iohzrd</p>"
				 "</body></html>",
				 g_motd, g_pubkey, json);
			snprintf(hdr, sizeof hdr,
				 "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n"
				 "Content-Length: %zu\r\nConnection: close\r\n\r\n",
				 strlen(body));
		}
		write_all(c, hdr, strlen(hdr));
		write_all(c, body, strlen(body));
		close(c);
	}
	close(fd);
	return NULL;
}

int prime_stats_start(const char *listen_addr, prime_pool *pool, const char *motd,
		      const char *pubkey_hex, const prime_config_opts *opt,
		      const char *datum_host, uint16_t datum_port, const char *source_url)
{
	char host[128];
	const char *colon;
	unsigned long port;
	int fd, on = 1;
	struct sockaddr_in addr;
	pthread_t th;

	if (!listen_addr || !listen_addr[0] || !pool) {
		return -1;
	}
	colon = strrchr(listen_addr, ':');
	if (!colon) {
		return -1;
	}
	if ((size_t)(colon - listen_addr) >= sizeof host) {
		return -1;
	}
	memcpy(host, listen_addr, (size_t)(colon - listen_addr));
	host[colon - listen_addr] = 0;
	port = strtoul(colon + 1, NULL, 10);
	g_pool = pool;
	snprintf(g_motd, sizeof g_motd, "%s", motd ? motd : "");
	snprintf(g_pubkey, sizeof g_pubkey, "%s", pubkey_hex ? pubkey_hex : "");
	snprintf(g_source_url, sizeof g_source_url, "%s", source_url ? source_url : "");
	copy_url_host(source_url, g_datum_host, sizeof g_datum_host);
	if (datum_host && datum_host[0] && strcmp(datum_host, "0.0.0.0") != 0
	    && strcmp(datum_host, "127.0.0.1") != 0) {
		snprintf(g_datum_host, sizeof g_datum_host, "%s", datum_host);
	}
	g_datum_port = datum_port;
	if (opt) {
		g_fee_bps = opt->fee_bps;
		g_fee_after_first = opt->fee_after_first_block ? 1 : 0;
		g_min_payout = opt->min_payout;
		g_min_diff = opt->min_difficulty;
		g_window_multiple = opt->window_multiple;
		g_window_floor = opt->window_floor;
		g_abw_enabled = !opt->abw_disabled;
		g_require_split = opt->require_split;
		g_sv1_port = 0;
		if (opt->stratum_listen && opt->stratum_listen[0]) {
			const char *colon = strrchr(opt->stratum_listen, ':');
			if (colon) {
				g_sv1_port = (uint16_t)strtoul(colon + 1, NULL, 10);
			}
		}
	}
	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		return -1;
	}
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
	memset(&addr, 0, sizeof addr);
	addr.sin_family = AF_INET;
	addr.sin_port = htons((uint16_t)port);
	if (inet_pton(AF_INET, host, &addr.sin_addr) != 1 ||
	    bind(fd, (struct sockaddr *)&addr, sizeof addr) != 0 || listen(fd, 8) != 0) {
		close(fd);
		return -1;
	}
	if (pthread_create(&th, NULL, stats_thread, (void *)(intptr_t)fd) != 0) {
		close(fd);
		return -1;
	}
	pthread_detach(th);
	fprintf(stderr, "prime: stats on %s\n", listen_addr);
	return 0;
}
