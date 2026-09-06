/* AGPL section 13: offer corresponding source to network users.
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

static char g_public_url[256];
static char g_tar_path[512];
static int g_listen_fd = -1;

static int write_all_fd(int fd, const void *buf, size_t n)
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

static int find_tree(char *out, size_t out_len)
{
	char exe[512];
	ssize_t n = readlink("/proc/self/exe", exe, sizeof exe - 1);
	char *slash;
	if (n <= 0) {
		return -1;
	}
	exe[n] = 0;
	slash = strrchr(exe, '/');
	if (!slash) {
		return -1;
	}
	*slash = 0;
	slash = strrchr(exe, '/');
	if (slash && strcmp(slash, "/build") == 0) {
		*slash = 0;
	}
	if (strlen(exe) >= out_len) {
		return -1;
	}
	memcpy(out, exe, strlen(exe) + 1);
	return 0;
}

static int build_tarball(const char *tree)
{
	char cmd[1024];
	snprintf(g_tar_path, sizeof g_tar_path, "/tmp/c-datum-prime-source-%d.tar.gz", (int)getpid());
	snprintf(cmd, sizeof cmd,
		 "tar -C '%s' -czf '%s' --exclude=data --exclude=build --exclude=third_party "
		 "LICENSE NOTICE README.md CMakeLists.txt RATUM_PIN src 2>/dev/null",
		 tree, g_tar_path);
	if (system(cmd) != 0) {
		return -1;
	}
	return 0;
}

static void send_text(int fd, const char *ctype, const char *body)
{
	char hdr[256];
	int n = snprintf(hdr, sizeof hdr,
			 "HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %zu\r\n"
			 "Connection: close\r\n\r\n",
			 ctype, strlen(body));
	write_all_fd(fd, hdr, (size_t)n);
	write_all_fd(fd, body, strlen(body));
}

static void send_file(int fd, const char *path, const char *ctype, const char *name)
{
	FILE *f = fopen(path, "rb");
	char *buf;
	long sz;
	char hdr[320];
	if (!f) {
		send_text(fd, "text/plain", "source archive missing\n");
		return;
	}
	if (fseek(f, 0, SEEK_END) != 0) {
		fclose(f);
		send_text(fd, "text/plain", "source archive unreadable\n");
		return;
	}
	sz = ftell(f);
	rewind(f);
	if (sz < 0 || sz > 32 * 1024 * 1024) {
		fclose(f);
		send_text(fd, "text/plain", "source archive too large\n");
		return;
	}
	buf = malloc((size_t)sz);
	if (!buf || fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
		fclose(f);
		free(buf);
		send_text(fd, "text/plain", "source archive read failed\n");
		return;
	}
	fclose(f);
	snprintf(hdr, sizeof hdr,
		 "HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %ld\r\n"
		 "Content-Disposition: attachment; filename=\"%s\"\r\nConnection: close\r\n\r\n",
		 ctype, sz, name);
	write_all_fd(fd, hdr, strlen(hdr));
	write_all_fd(fd, buf, (size_t)sz);
	free(buf);
}

static void handle_http(int fd)
{
	char req[1024];
	ssize_t n = recv(fd, req, sizeof req - 1, 0);
	char page[2048];
	if (n <= 0) {
		return;
	}
	req[n] = 0;
	if (strncmp(req, "GET /source.tar.gz", 18) == 0) {
		send_file(fd, g_tar_path, "application/gzip", "c-datum-prime-source.tar.gz");
		return;
	}
	if (strncmp(req, "GET / ", 6) == 0 || strncmp(req, "GET /index", 10) == 0) {
		snprintf(page, sizeof page,
			 "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>c_datum_prime source</title></head>"
			 "<body><h1>c_datum_prime (C)</h1>"
			 "<p>GNU Affero GPL v3 or later. This is the corresponding source offer required by AGPL section 13.</p>"
			 "<p>Translated from RATUM Prime by iohzrd. CONVOY DATUM Gateway is separate MIT software.</p>"
			 "<p><a href=\"/source.tar.gz\">Download source tarball</a></p>"
			 "<p>Public URL: %s</p></body></html>\n",
			 g_public_url);
		send_text(fd, "text/html; charset=utf-8", page);
		return;
	}
	send_text(fd, "text/plain", "404\n");
}

static void *http_thread(void *arg)
{
	(void)arg;
	for (;;) {
		int c = accept(g_listen_fd, NULL, NULL);
		if (c < 0) {
			if (errno == EINTR) {
				continue;
			}
			break;
		}
		handle_http(c);
		close(c);
	}
	return NULL;
}

int prime_source_start(const char *listen_addr, const char *public_url)
{
	char host[128];
	const char *colon;
	unsigned long port;
	char *end = NULL;
	struct sockaddr_in addr;
	int on = 1;
	pthread_t th;
	char tree[512];

	if (!listen_addr || !public_url) {
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
	port = strtoul(colon + 1, &end, 10);
	if (!end || *end || port == 0 || port > 65535) {
		return -1;
	}
	snprintf(g_public_url, sizeof g_public_url, "%s", public_url);
	if (find_tree(tree, sizeof tree) != 0) {
		fprintf(stderr, "prime: could not locate source tree\n");
		return -1;
	}
	if (build_tarball(tree) != 0) {
		fprintf(stderr, "prime: could not pack source tarball from %s\n", tree);
		return -1;
	}
	g_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (g_listen_fd < 0) {
		return -1;
	}
	setsockopt(g_listen_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
	memset(&addr, 0, sizeof addr);
	addr.sin_family = AF_INET;
	addr.sin_port = htons((uint16_t)port);
	if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
		close(g_listen_fd);
		return -1;
	}
	if (bind(g_listen_fd, (struct sockaddr *)&addr, sizeof addr) != 0
	    || listen(g_listen_fd, 8) != 0) {
		perror("source listen");
		close(g_listen_fd);
		return -1;
	}
	if (pthread_create(&th, NULL, http_thread, NULL) != 0) {
		close(g_listen_fd);
		return -1;
	}
	pthread_detach(th);
	fprintf(stderr, "AGPL source offer on %s  (tarball %s)\n", listen_addr, g_tar_path);
	fprintf(stderr, "AGPL public URL %s\n", g_public_url);
	return 0;
}
