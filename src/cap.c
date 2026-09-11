/* 120-block nethash cap: measure pool share, refuse/kick newest SV1.
 * Copyright (C) Blockvase contributors
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
#include <unistd.h>

#define CAP_MAX_CLIENTS 49152
#define CAP_HTTP_MAX (8 * 1024 * 1024)

typedef struct {
	int tid;
	int cid;
	uint64_t connect_tsms;
	uint64_t unique_id;
	double hs;
} cap_client;

static pthread_mutex_t g_snap_mu = PTHREAD_MUTEX_INITIALIZER;
static prime_nethash_snap g_snap;
static int g_admit = 1;

void prime_cap_policy(double pool_frac, double datum_frac, int admit_now,
		      int *admit_out, int *kick_all, int *need_shed)
{
	int admit = 1, all = 0, shed = 0;
	if (datum_frac > PRIME_CAP_FRACTION) {
		admit = 0;
		all = 1;
		shed = 1;
	} else if (pool_frac > PRIME_CAP_FRACTION) {
		admit = 0;
		shed = 1;
	} else if (!admit_now && pool_frac > PRIME_CAP_RESUME) {
		admit = 0;
		shed = pool_frac > PRIME_CAP_KICK_TO;
	}
	if (admit_out) {
		*admit_out = admit;
	}
	if (kick_all) {
		*kick_all = all;
	}
	if (need_shed) {
		*need_shed = shed;
	}
}

void prime_nethash_get(prime_nethash_snap *out)
{
	if (!out) {
		return;
	}
	pthread_mutex_lock(&g_snap_mu);
	*out = g_snap;
	if (!g_snap.updated_at) {
		out->sv1_admit = 1;
	}
	pthread_mutex_unlock(&g_snap_mu);
}

int prime_nethash_json(char *out, size_t out_len)
{
	prime_nethash_snap s;
	if (!out || !out_len) {
		return -1;
	}
	prime_nethash_get(&s);
	return snprintf(out, out_len,
			"{\"blocks\":%u,\"network_hs\":%.8g,\"pool_hs\":%.8g,"
			"\"datum_hs\":%.8g,\"sv1_hs\":%.8g,\"pool_fraction\":%.8g,"
			"\"cap_fraction\":%.4f,\"kick_to_fraction\":%.4f,"
			"\"resume_fraction\":%.4f,\"sv1_admit\":%s,"
			"\"lookback_sec\":%llu,\"oldest_share_at\":%llu,"
			"\"share_count\":%llu,\"updated_at\":%llu,"
			"\"interval_sec\":%u}",
			(unsigned)PRIME_NETHASH_BLOCKS, s.network_hs, s.pool_hs,
			s.datum_hs, s.sv1_hs, s.pool_fraction,
			PRIME_CAP_FRACTION, PRIME_CAP_KICK_TO, PRIME_CAP_RESUME,
			s.sv1_admit ? "true" : "false",
			(unsigned long long)s.lookback_sec,
			(unsigned long long)s.oldest_share_at,
			(unsigned long long)s.share_count,
			(unsigned long long)s.updated_at,
			(unsigned)PRIME_CAP_INTERVAL_SEC);
}

static void json_escape(const char *in, char *out, size_t out_len)
{
	size_t i = 0, o = 0;
	if (!out || !out_len) {
		return;
	}
	out[0] = 0;
	if (!in) {
		return;
	}
	for (; in[i] && o + 2 < out_len; i++) {
		if (in[i] == '"' || in[i] == '\\') {
			if (o + 3 >= out_len) {
				break;
			}
			out[o++] = '\\';
			out[o++] = in[i];
		} else if ((unsigned char)in[i] < 32) {
			continue;
		} else {
			out[o++] = in[i];
		}
	}
	out[o] = 0;
}

static int parse_sv1_api(const char *url, char *host, size_t host_len, uint16_t *port)
{
	const char *s = url ? url : "";
	const char *colon;
	if (strncmp(s, "http://", 7) == 0) {
		s += 7;
	}
	colon = strrchr(s, ':');
	if (!colon || colon == s) {
		snprintf(host, host_len, "%s", s[0] ? s : "127.0.0.1");
		*port = 7153;
		return 0;
	}
	if ((size_t)(colon - s) >= host_len) {
		return -1;
	}
	memcpy(host, s, (size_t)(colon - s));
	host[colon - s] = 0;
	*port = (uint16_t)strtoul(colon + 1, NULL, 10);
	if (!*port) {
		*port = 7153;
	}
	return 0;
}

static int http_post_json(const char *host, uint16_t port, const char *body,
			  char **resp_out, size_t *resp_len)
{
	int fd;
	struct sockaddr_in addr;
	char hdr[256];
	char *buf = NULL;
	size_t cap = 4096, n = 0, need;
	ssize_t r;
	char *hdr_end, *cl;
	size_t body_off = 0, content_len = 0;

	if (resp_out) {
		*resp_out = NULL;
	}
	if (resp_len) {
		*resp_len = 0;
	}
	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		return -1;
	}
	memset(&addr, 0, sizeof addr);
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	if (inet_pton(AF_INET, host, &addr.sin_addr) != 1
	    || connect(fd, (struct sockaddr *)&addr, sizeof addr) != 0) {
		close(fd);
		return -1;
	}
	need = strlen(body);
	if (snprintf(hdr, sizeof hdr,
		     "POST /cmd HTTP/1.1\r\nHost: %s:%u\r\n"
		     "Content-Type: application/json\r\nContent-Length: %zu\r\n"
		     "Connection: close\r\n\r\n",
		     host, (unsigned)port, need) >= (int)sizeof hdr) {
		close(fd);
		return -1;
	}
	if (send(fd, hdr, strlen(hdr), MSG_NOSIGNAL) < 0
	    || send(fd, body, need, MSG_NOSIGNAL) < 0) {
		close(fd);
		return -1;
	}
	buf = malloc(cap);
	if (!buf) {
		close(fd);
		return -1;
	}
	for (;;) {
		if (n + 2048 >= cap) {
			char *nb;
			if (cap >= CAP_HTTP_MAX) {
				break;
			}
			nb = realloc(buf, cap * 2);
			if (!nb) {
				free(buf);
				close(fd);
				return -1;
			}
			buf = nb;
			cap *= 2;
		}
		r = recv(fd, buf + n, cap - n - 1, 0);
		if (r < 0) {
			if (errno == EINTR) {
				continue;
			}
			free(buf);
			close(fd);
			return -1;
		}
		if (r == 0) {
			break;
		}
		n += (size_t)r;
		buf[n] = 0;
		if (!body_off) {
			hdr_end = strstr(buf, "\r\n\r\n");
			if (hdr_end) {
				body_off = (size_t)(hdr_end - buf) + 4;
				cl = strstr(buf, "Content-Length:");
				if (cl && cl < hdr_end) {
					content_len = strtoul(cl + 15, NULL, 10);
				}
			}
		}
		if (body_off && content_len && n >= body_off + content_len) {
			break;
		}
	}
	close(fd);
	if (!body_off || n < body_off) {
		free(buf);
		return -1;
	}
	if (strncmp(buf, "HTTP/1.1 200", 12) != 0 && strncmp(buf, "HTTP/1.0 200", 12) != 0) {
		free(buf);
		return -1;
	}
	if (resp_out) {
		size_t blen = n - body_off;
		char *body_copy = malloc(blen + 1);
		if (!body_copy) {
			free(buf);
			return -1;
		}
		memcpy(body_copy, buf + body_off, blen);
		body_copy[blen] = 0;
		*resp_out = body_copy;
		if (resp_len) {
			*resp_len = blen;
		}
	}
	free(buf);
	return 0;
}

static int json_u64_field(const char *obj, const char *end, const char *key, uint64_t *out)
{
	char pat[64];
	const char *f;
	char *e;
	if (snprintf(pat, sizeof pat, "\"%s\":", key) >= (int)sizeof pat) {
		return -1;
	}
	f = strstr(obj, pat);
	if (!f || f >= end) {
		return -1;
	}
	f += strlen(pat);
	while (f < end && (*f == ' ' || *f == '\t')) {
		f++;
	}
	*out = (uint64_t)strtoull(f, &e, 10);
	if (e == f) {
		return -1;
	}
	return 0;
}

static int json_f64_field(const char *obj, const char *end, const char *key, double *out)
{
	char pat[64];
	const char *f;
	char *e;
	if (snprintf(pat, sizeof pat, "\"%s\":", key) >= (int)sizeof pat) {
		return -1;
	}
	f = strstr(obj, pat);
	if (!f || f >= end) {
		return -1;
	}
	f += strlen(pat);
	while (f < end && (*f == ' ' || *f == '\t')) {
		f++;
	}
	*out = strtod(f, &e);
	if (e == f) {
		return -1;
	}
	return 0;
}

static int parse_clients(const char *json, cap_client *out, size_t max, size_t *n_out)
{
	const char *arr, *p;
	size_t n = 0;
	int depth = 0;
	if (n_out) {
		*n_out = 0;
	}
	if (!json || !out || !max) {
		return -1;
	}
	arr = strstr(json, "\"clients\"");
	if (!arr) {
		return 0;
	}
	arr = strchr(arr, '[');
	if (!arr) {
		return -1;
	}
	p = arr + 1;
	while (*p) {
		const char *obj, *end;
		uint64_t tid = 0, cid = 0, ts = 0, uid = 0;
		double hs = 0;
		if (*p == ']') {
			break;
		}
		if (*p != '{') {
			p++;
			continue;
		}
		obj = p;
		depth = 0;
		for (end = p; *end; end++) {
			if (*end == '{') {
				depth++;
			} else if (*end == '}') {
				depth--;
				if (depth == 0) {
					end++;
					break;
				}
			}
		}
		if (json_u64_field(obj, end, "tid", &tid) == 0
		    && json_u64_field(obj, end, "cid", &cid) == 0) {
			json_u64_field(obj, end, "connect_tsms", &ts);
			json_u64_field(obj, end, "unique_id", &uid);
			json_f64_field(obj, end, "hs", &hs);
			if (n < max) {
				out[n].tid = (int)tid;
				out[n].cid = (int)cid;
				out[n].connect_tsms = ts;
				out[n].unique_id = uid;
				out[n].hs = hs > 0 ? hs : 0;
				n++;
			}
		}
		p = end;
	}
	if (n_out) {
		*n_out = n;
	}
	return 0;
}

static int count_client_objects(const char *json, unsigned *n_out)
{
	const char *arr, *p;
	int depth = 0;
	unsigned n = 0;

	if (n_out) {
		*n_out = 0;
	}
	if (!json) {
		return -1;
	}
	arr = strstr(json, "\"clients\"");
	if (!arr) {
		return 0;
	}
	arr = strchr(arr, '[');
	if (!arr) {
		return -1;
	}
	p = arr + 1;
	while (*p && *p != ']') {
		if (*p == '"') {
			p++;
			while (*p && *p != '"') {
				if (*p == '\\' && p[1]) {
					p++;
				}
				p++;
			}
			if (*p == '"') {
				p++;
			}
			continue;
		}
		if (*p == '{') {
			if (depth == 0) {
				n++;
			}
			depth++;
		} else if (*p == '}') {
			if (depth) {
				depth--;
			}
		}
		p++;
	}
	if (n_out) {
		*n_out = n;
	}
	return 0;
}

static int gw_cmd(const char *host, uint16_t port, const char *password, const char *cmd_json,
		  char **resp);

static void refresh_sv1_connected(const char *host, uint16_t port, const char *password)
{
	char *resp = NULL;
	unsigned n = 0;

	if (!password || !password[0] || !host || !host[0]) {
		return;
	}
	if (gw_cmd(host, port, password, "{\"cmd\":\"list_clients\"}", &resp) != 0 || !resp) {
		free(resp);
		return;
	}
	if (count_client_objects(resp, &n) == 0) {
		prime_sv1_note_connected(n);
	}
	free(resp);
}

static int cmp_newest(const void *a, const void *b)
{
	const cap_client *x = a, *y = b;
	if (x->connect_tsms < y->connect_tsms) {
		return 1;
	}
	if (x->connect_tsms > y->connect_tsms) {
		return -1;
	}
	return 0;
}

static int gw_cmd(const char *host, uint16_t port, const char *password, const char *cmd_json,
		  char **resp)
{
	char pw[256];
	char *body;
	size_t n;
	int rc;
	json_escape(password, pw, sizeof pw);
	n = strlen(cmd_json) + strlen(pw) + 32;
	body = malloc(n);
	if (!body) {
		return -1;
	}
	snprintf(body, n, "{\"password\":\"%s\",%s", pw, cmd_json[0] == '{' ? cmd_json + 1 : cmd_json);
	rc = http_post_json(host, port, body, resp, NULL);
	free(body);
	return rc;
}

static int set_accept(const char *host, uint16_t port, const char *password, int accept)
{
	char cmd[80];
	char *resp = NULL;
	int rc;
	snprintf(cmd, sizeof cmd, "{\"cmd\":\"set_accept_sv1\",\"accept\":%s}",
		 accept ? "true" : "false");
	rc = gw_cmd(host, port, password, cmd, &resp);
	free(resp);
	return rc;
}

static int list_clients(const char *host, uint16_t port, const char *password,
			cap_client *out, size_t max, size_t *n)
{
	char *resp = NULL;
	int rc;
	rc = gw_cmd(host, port, password, "{\"cmd\":\"list_clients\"}", &resp);
	if (rc != 0 || !resp) {
		free(resp);
		return -1;
	}
	rc = parse_clients(resp, out, max, n);
	free(resp);
	return rc;
}

static int kill_client(const char *host, uint16_t port, const char *password, const cap_client *c)
{
	char cmd[256];
	char *resp = NULL;
	int rc;
	snprintf(cmd, sizeof cmd,
		 "{\"cmd\":\"kill_client\",\"tid\":%d,\"cid\":%d,\"t\":%llu,\"id\":%llu}",
		 c->tid, c->cid, (unsigned long long)c->connect_tsms,
		 (unsigned long long)c->unique_id);
	rc = gw_cmd(host, port, password, cmd, &resp);
	free(resp);
	return rc;
}

typedef struct {
	char datadir[512];
	char api_host[128];
	uint16_t api_port;
	prime_pool *pool;
} cap_arg;

static void refresh_snap(prime_pool *pool, const char *datadir, int admit)
{
	prime_nethash_snap s;
	uint64_t now = (uint64_t)time(NULL);
	uint64_t since = 0, lookback = 0, total = 0, sv1 = 0, oldest = 0, count = 0;
	double nethash = 0;
	memset(&s, 0, sizeof s);
	s.sv1_admit = admit;
	s.updated_at = now;
	if (datadir && datadir[0]
	    && prime_rpc_networkhashps(datadir, PRIME_NETHASH_BLOCKS, &nethash) == 0) {
		s.network_hs = nethash;
		s.have_nethash = 1;
	}
	if (datadir && datadir[0]
	    && prime_rpc_lookback_since(datadir, PRIME_NETHASH_BLOCKS, &since) == 0
	    && now > since) {
		lookback = now - since;
	}
	if (lookback < 600) {
		lookback = (uint64_t)PRIME_NETHASH_BLOCKS * 600ull;
		if (now > lookback) {
			since = now - lookback;
		} else {
			since = 0;
		}
	}
	s.lookback_sec = lookback;
	if (pool && prime_pool_work_since(pool, since, &total, &sv1, &oldest, &count) == 0) {
		s.pool_hs = prime_work_to_hashrate_hs(total, lookback);
		s.sv1_hs = prime_work_to_hashrate_hs(sv1, lookback);
		s.datum_hs = prime_work_to_hashrate_hs(total > sv1 ? total - sv1 : 0, lookback);
		s.oldest_share_at = oldest;
		s.share_count = count;
	}
	if (s.have_nethash && s.network_hs > 0) {
		s.pool_fraction = s.pool_hs / s.network_hs;
	}
	pthread_mutex_lock(&g_snap_mu);
	g_snap = s;
	pthread_mutex_unlock(&g_snap_mu);
}

static void *cap_thread(void *arg)
{
	cap_arg *a = arg;
	const char *password;
	int first = 1;
	int accept_synced = 0;
	if (!a) {
		return NULL;
	}
	password = getenv("PRIME_SV1_API_PASSWORD");
	if (password && password[0]) {
		refresh_sv1_connected(a->api_host, a->api_port, password);
	}
	for (;;) {
		prime_nethash_snap s;
		int admit = 0, kick_all = 0, shed = 0, admit_changed;
		double pool_frac, datum_frac;
		if (first) {
			sleep(15);
			first = 0;
		} else {
			sleep(PRIME_CAP_INTERVAL_SEC);
		}
		refresh_snap(a->pool, a->datadir, g_admit);
		if (password && password[0]) {
			refresh_sv1_connected(a->api_host, a->api_port, password);
		}
		prime_nethash_get(&s);
		if (!s.have_nethash || s.network_hs <= 0) {
			fprintf(stderr, "prime: nethash RPC unavailable; SV1 cap not enforced this tick\n");
			continue;
		}
		pool_frac = s.pool_fraction;
		datum_frac = s.network_hs > 0 ? s.datum_hs / s.network_hs : 0;
		prime_cap_policy(pool_frac, datum_frac, g_admit, &admit, &kick_all, &shed);
		admit_changed = (admit != g_admit);
		if (admit_changed) {
			fprintf(stderr, "prime: SV1 admit %s (pool %.4f%% of 120-block nethash)\n",
				admit ? "open" : "closed", pool_frac * 100.0);
		}
		g_admit = admit;
		refresh_snap(a->pool, a->datadir, g_admit);
		if (password && password[0] && (admit_changed || !accept_synced)) {
			if (set_accept(a->api_host, a->api_port, password, g_admit) != 0) {
				fprintf(stderr, "prime: public gateway set_accept_sv1 failed\n");
			} else {
				accept_synced = 1;
			}
		} else if (shed || !g_admit) {
			fprintf(stderr, "prime: PRIME_SV1_API_PASSWORD unset; cannot refuse/kick SV1\n");
			continue;
		}
		if (!shed || !password || !password[0]) {
			if (s.updated_at) {
				fprintf(stderr,
					"prime: nethash %.4e pool %.4e (%.6f%%) datum %.4e sv1 %.4e admit=%d\n",
					s.network_hs, s.pool_hs, pool_frac * 100.0, s.datum_hs,
					s.sv1_hs, g_admit);
			}
			continue;
		}
		{
			cap_client *cls = calloc(CAP_MAX_CLIENTS, sizeof *cls);
			size_t n = 0, i;
			double live = 0, budget;
			if (!cls) {
				continue;
			}
			if (list_clients(a->api_host, a->api_port, password, cls, CAP_MAX_CLIENTS, &n) != 0) {
				fprintf(stderr, "prime: public gateway list_clients failed\n");
				free(cls);
				continue;
			}
			prime_sv1_note_connected((unsigned)n);
			qsort(cls, n, sizeof cls[0], cmp_newest);
			for (i = 0; i < n; i++) {
				live += cls[i].hs;
			}
			budget = PRIME_CAP_KICK_TO * s.network_hs - s.datum_hs;
			if (kick_all || budget < 0) {
				budget = 0;
			}
			for (i = 0; i < n && (kick_all || live > budget); i++) {
				if (kill_client(a->api_host, a->api_port, password, &cls[i]) == 0) {
					fprintf(stderr,
						"prime: kicked SV1 %d/%d (%.4e H/s, newest-first)\n",
						cls[i].tid, cls[i].cid, cls[i].hs);
					live -= cls[i].hs;
				} else {
					fprintf(stderr, "prime: kick SV1 %d/%d failed\n",
						cls[i].tid, cls[i].cid);
				}
			}
			free(cls);
			fprintf(stderr,
				"prime: nethash %.4e pool %.4e (%.6f%%) admit=%d kicked-newest sv1\n",
				s.network_hs, s.pool_hs, pool_frac * 100.0, g_admit);
		}
	}
	free(a);
	return NULL;
}

int prime_cap_start(const char *datadir, prime_pool *pool, const char *sv1_api)
{
	cap_arg *a;
	pthread_t th;
	if (!pool) {
		return -1;
	}
	a = calloc(1, sizeof *a);
	if (!a) {
		return -1;
	}
	if (datadir && datadir[0]) {
		snprintf(a->datadir, sizeof a->datadir, "%s", datadir);
	}
	if (parse_sv1_api(sv1_api ? sv1_api : "http://127.0.0.1:7153",
			  a->api_host, sizeof a->api_host, &a->api_port) != 0) {
		free(a);
		return -1;
	}
	a->pool = pool;
	g_admit = 1;
	refresh_snap(pool, datadir, 1);
	if (pthread_create(&th, NULL, cap_thread, a) != 0) {
		free(a);
		return -1;
	}
	pthread_detach(th);
	fprintf(stderr, "prime: 120-block SV1 cap every %us via %s:%u (25%% / kick 23%% / resume 22%%)\n",
		(unsigned)PRIME_CAP_INTERVAL_SEC, a->api_host, (unsigned)a->api_port);
	return 0;
}
