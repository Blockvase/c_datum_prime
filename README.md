# c_datum_prime

Public repo: [github.com/Blockvase/c_datum_prime](https://github.com/Blockvase/c_datum_prime)

A C translation of [RATUM Prime](https://github.com/iohzrd/ratum) by iohzrd.
License: GNU Affero GPL v3 or later. See `LICENSE` and `NOTICE`.

This repo is **only the DATUM pool server (Prime)**. It is not a full mining
stack, not a public Stratum server, and not the LAN miner gateway. Cloning
and running this binary will not hash or pay anyone by itself.

To get a Knots node, CONVOY DATUM Gateway, and miners working first, follow
[bitcoin-blake2b.org/mining](https://bitcoin-blake2b.org/mining). That guide
leaves you in **solo** mode (`datum.pool_host` empty,
`datum.pooled_mining_only` false).

CONVOY DATUM Gateway is separate MIT software. Do not merge this tree into it.

## After the mining guide: point CONVOY DATUM at this pool

When Knots and CONVOY DATUM are up, replace the `datum` object in
`datum_gateway_config.json` with:

```json
"datum": {
    "pooled_mining_only": true,
    "pool_host": "pool.blockvase.com",
    "pool_port": 28915,
    "pool_pubkey": "d89f714cfe7bd9022794b42e2b9b7c196cdd0e16165df0300d788a1b18a86da20654de460ece16e2a2e88d1f8ad316f728c2b5b731d259afd55229375c905439"
}
```

Restart CONVOY DATUM. Keep your ASIC on the gateway's Stratum port (`23334` in
the guide). Do not point miners at Prime.

If you run your own Prime instead of Blockvase's, use the `pool_pubkey`
printed at startup, `pool_host` `127.0.0.1` (or that host's public name),
and `pool_port` `28915`. From this LAN, `pool.blockvase.com:28915` may
time out (no hairpin); use `192.168.1.206`.

## What works now

Aligned with RATUM Prime (`698a236`) on the live path:

1. Keys, listen, CONVOY DATUM/RATUM hello (v1 and v3), signed 0x99 config.
2. Coinbaser split from a durable share ledger (RATUM window math, fee
   `--fee-bps`, optional `--fee-after-first-block` to stay at 0% until the
   first recorded pool block then apply `--fee-bps` permanently, `--min-payout`
   546). Identities are `username` up to the
   first `.`. Mainnet P2PKH `1...`, P2SH `3...`, SegWit `bc1q...`, and
   Taproot `bc1p...` become scripts; up to 128 split outputs are served.
3. `require_split` after a 10s grace (RATUM): keyed off the job's
   coinbaser id, not the share's stratum class. `--no-require-split` to
   turn off.
4. Share PoW (header-v2, twelve zero bytes in the coinbase hole), replay
   guard, credit into the ledger.
5. v3 ABW: 0xA8 notices, key in H1, mask, 0xA5 receipts, 0x8F exact ref,
   rotate, delayed 0xA9 reveal. `--abw-disabled` if you need the old path.
6. Resume tokens honored (ABW keys + coinbaser id).
7. Block relay: nbits, `0x50 0x12`/`0x92`, merkle, `submitblock` via
   `bitcoin-cli` cookie, hex under `data/blocks/`. Parses `0x90`/`0x91`/`0x94`.
8. Bulk framing (`DBF\x01` / `DBA\x01`) for large replies.
9. Stats HTTP (default `0.0.0.0:28917`, `/`, `/stats.json`, and `/pool.json`
   for the Blockvase website relay).
10. One thread per gateway. `--self-test` covers framing, handshake, header
    vectors, split 75/25 and >8 outputs, Base58Check, bech32, zero xor mask,
    and `require_split` keyed off the job coinbaser id.

AGPL section 13: corresponding source is this GitHub repo and
`http://pool.blockvase.com:28916/` (also in the MOTD). Forward TCP 28916
(and 28917 if you want stats off-LAN). The tarball excludes `data/`
(keys, ledger) and `build/`.

systemd unit: `contrib/c-datum-prime.service` (`TimeoutStopSec=15`,
`KillMode=mixed`; SIGTERM can hang on an open DATUM session).
This host uses the user unit `contrib/c-datum-prime.user.service`
(`systemctl --user enable --now c-datum-prime`). The website relay is
`blockvase-relay` (`systemctl --user`). A system-wide template is
`contrib/c-datum-prime.service`.

## Pool Info JSON

`GET /pool.json` on the stats listener returns public pool metadata for the
Blockvase Pool tab. It includes `schema_version`, endpoint, source URL,
pubkey, fee, payout address types, connected DATUM clients, share-window
progress, blocks found, a 3-hour hashrate average (`hashrate_hs`, H/s:
accepted share difficulty × 2^32 / 10800), and miners by window work
percent plus that same 3-hour hashrate. `GET /shares.json` (also `/tides.json`)
is the ordered share log for that window: `at`, `difficulty`, `id`, `hash`,
oldest first. Page with `?after=<hash>&limit=500` (limit max 2000). The live
window is the share file plus the last known target (`ledger.window`). Prime
does not trim to the startup floor while `getdifficulty` is down. Optional
`--stratum-listen` is a second DATUM bind for a public Stratum V1 gateway.
Shares on that bind pay 2.3% (2% to DATUM identities in the window, 0.3%
to the payout script). DATUM clients keep `--fee-bps` only. Public miners
connect to `stratum_v1_url` (`stratum+tcp://pool.blockvase.com:3333`), not
the internal `--stratum-listen` port. Miner rows include `kind` (`datum`,
`sv1`, or `mixed`) plus `datum_work` / `public_work`.
`window_percent` is the payout split from window work, not the 3-hour
hashrate. It intentionally does not include RPC credentials, private keys,
or local ledger file paths.

## Build

Needs libsodium and CMake.

```
cmake -S . -B build
cmake --build build
./build/c-datum-prime --self-test
```

## Run (localhost only)

After the [mining guide](https://bitcoin-blake2b.org/mining) you already have
Knots. Then:

```
./build/c-datum-prime
```

Keys, ledger, and submitted-block files default to `data/` next to the
project root (the parent of `build/`), from `/proc/self/exe`. They do not
depend on the current working directory or a hardcoded home path. Bitcoin
RPC defaults to `$HOME/.bitcoin`. Override with `--bitcoin-datadir`,
`--keys`, `--ledger`, `--block-dir`, and `--payout-script`.

Do not forward 8332, 7152, or 23334. Forward 28915 when this Prime is
public, and 28916 if remote users should fetch source (AGPL section 13).

Use a distinct process name from `datum_gateway` so Knots
`blocknotify=killall -USR1 datum_gateway` does not signal Prime.

## systemd

User unit (starts at login, or at boot if linger is on):

```
mkdir -p ~/.local/lib ~/.config/systemd/user
ln -sfn /path/to/c_datum_prime ~/.local/lib/c-datum-prime
cp contrib/c-datum-prime.user.service ~/.config/systemd/user/c-datum-prime.service
loginctl enable-linger "$USER"
systemctl --user daemon-reload
systemctl --user enable --now c-datum-prime.service
```

System unit is `contrib/c-datum-prime.service` (`WantedBy=multi-user.target`).
If you move the checkout, retarget the symlink. Do not add `--keys`,
`--ledger`, or `--block-dir` to the unit.

## Isolation

- Own tree, keys, ports, and unit.
- Knots RPC stays on localhost.
- This binary binds loopback until you pass `--listen` with another address.
