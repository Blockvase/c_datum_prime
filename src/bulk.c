/* Translated from RATUM core/src/datum/bulk.rs by iohzrd.
 * Copyright (C) iohzrd and RATUM contributors
 * Copyright (C) Blockvase contributors (C translation)
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#include "prime.h"

#include <stdlib.h>
#include <string.h>

static const unsigned char DBF[4] = { 'D', 'B', 'F', 0x01 };
static const unsigned char DBA[4] = { 'D', 'B', 'A', 0x01 };

int prime_bulk_ack(uint32_t id, uint32_t next_offset, unsigned char out[12])
{
	memcpy(out, DBA, 4);
	out[4] = (unsigned char)id;
	out[5] = (unsigned char)(id >> 8);
	out[6] = (unsigned char)(id >> 16);
	out[7] = (unsigned char)(id >> 24);
	out[8] = (unsigned char)next_offset;
	out[9] = (unsigned char)(next_offset >> 8);
	out[10] = (unsigned char)(next_offset >> 16);
	out[11] = (unsigned char)(next_offset >> 24);
	return 0;
}

int prime_bulk_ingest(unsigned char **acc, size_t *acc_len, size_t *acc_cap, uint32_t *id,
		      uint32_t *total, uint32_t *got, const unsigned char *plain, size_t plain_len,
		      int *complete)
{
	uint32_t fid, ftotal, foff;
	size_t chunk;

	*complete = 0;
	if (plain_len < 16 || memcmp(plain, DBF, 4) != 0) {
		return -1;
	}
	fid = (uint32_t)plain[4] | ((uint32_t)plain[5] << 8) | ((uint32_t)plain[6] << 16)
	      | ((uint32_t)plain[7] << 24);
	ftotal = (uint32_t)plain[8] | ((uint32_t)plain[9] << 8) | ((uint32_t)plain[10] << 16)
		 | ((uint32_t)plain[11] << 24);
	foff = (uint32_t)plain[12] | ((uint32_t)plain[13] << 8) | ((uint32_t)plain[14] << 16)
	       | ((uint32_t)plain[15] << 24);
	chunk = plain_len - 16;
	if (!fid || !ftotal || ftotal > PRIME_MAX_CMD_LEN || !chunk || chunk > 16384) {
		return -1;
	}
	if (*acc && *id && fid != *id) {
		return -1;
	}
	if (*acc && *total && ftotal != *total) {
		return -1;
	}
	if (foff != *got) {
		return -1;
	}
	if (!*acc) {
		*acc = malloc(ftotal);
		if (!*acc) {
			return -1;
		}
		*acc_cap = ftotal;
		*acc_len = 0;
		*id = fid;
		*total = ftotal;
		*got = 0;
	}
	if (foff + chunk > *total) {
		return -1;
	}
	memcpy(*acc + foff, plain + 16, chunk);
	*got = foff + (uint32_t)chunk;
	*acc_len = *got;
	if (*got == *total) {
		*complete = 1;
	}
	return 0;
}
