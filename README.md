# app-cloudflare

esp-claw WASM app `cf`: manage Cloudflare through the device's `cloudflare` credential profile. The app never sees the API token; the firmware adds it to each request.

Successor of [app-cf-dns](https://github.com/esp-claw/app-cf-dns) (read-only zones/records). The app name changed to `cf`, so remove `/apps/cf_dns/` from the device when you install this one.

## Tools

| Tool | Purpose |
|---|---|
| `cf_zones(verify?)` | Zones of the account: name, status, plan, id. With `verify=true` it also checks the token (`/accounts/{id}/tokens/verify`) |
| `cf_dns_list(zone, type?, name?)` | DNS records as rows `[name, type, content, ttl, proxied, id]`. Names are relative to the zone (`@` = apex), and `ttl` 1 means automatic |
| `cf_dns_upsert(zone, type, name, content, ttl?, proxied?, record_id?)` | Creates the record, or updates the one record with this name and type. Pass `record_id` when several match. An unchanged record is not written |
| `cf_dns_delete(zone, record_id \| name+type)` | Deletes one record |
| `cf_purge(zone, urls? \| everything?)` | Purges up to 30 full URLs, or everything |
| `cf_tunnels()` | Cloudflare Tunnels: name, status, connection count, data centers, since, id |
| `cf_workers()` | Workers scripts: name, last modified date, handlers |
| `cf_analytics(zone, since_hours=24)` | HTTP traffic for 1-72 hours: requests, cached, bytes, threats, page views, requests per hour |

`zone` takes a zone name (`example.com`) or a 32-character zone id. Results are compact JSON (`cols` plus `rows`, trimmed fields), not raw API responses.

**Confirmations:** `cf_dns_upsert`, `cf_dns_delete` and `cf_purge` send POST/PATCH/DELETE requests. The firmware asks for confirmation in Telegram (✅ Einmal / ❌ Abbrechen) and refuses these requests outside an allowed Telegram chat. **`cf_analytics` asks too.** The GraphQL Analytics API only accepts POST, so the firmware treats the call as a mutation even though it only reads.

## Device profile

Add this entry to `api_profiles` in the device config. The token is an **account-owned** API token, so `/user/tokens/verify` does not work with it. The app finds the account id through `GET /accounts` and caches it in its key-value store.

```json
{"name": "cloudflare", "base_url": "https://api.cloudflare.com/client/v4", "hosts": ["api.cloudflare.com"],
 "auth": {"type": "bearer", "token": "<CLOUDFLARE_ACCOUNT_API_TOKEN>"}}
```

Token permissions, read-only: Zone:Read, DNS:Read, Analytics:Read, Account Settings:Read, Cloudflare Tunnel:Read, Workers Scripts:Read. Add DNS:Edit for upsert/delete and Cache Purge:Purge for purging. If the token can see several accounts, the app uses the first one.

## Build

```sh
git clone --recursive https://github.com/esp-claw/app-cloudflare.git
cd app-cloudflare && ./sdk/build-app.sh .
```

The build needs clang with the wasm32 target and wasm-ld (Debian/Ubuntu: `apt install clang lld`). It writes `build/app.wasm` (about 34 KB) and `build/manifest.json` (128 KB memory, 15 s per call). CI builds every push, checks the manifest and the module with the SDK's `manifest_check.py` and `wasm_check.py`, and attaches both files to releases.

## Install

Install a signed release in Telegram (see [Releases](#releases)):

```
/app install https://github.com/esp-claw/app-cloudflare/releases/download/v1.0.0/cf-1.0.0.ecapp
```

The device must trust the esp-claw key: `app_trusted_keys` must contain `XHQYDdKaRZ6pNzXYcrGAB8bTyPa3D22NU+lVzAt2Acw=` (see [trusted keys](https://github.com/esp-claw/app-sdk#trusted-keys)). The device asks for confirmation before installing. To update, send `/app update cf <url of the newer .ecapp>`. `/app remove cf` deletes the app and its data.

To test a local build, use a development device with `app_allow_unsigned` set to `true`. Copy `build/manifest.json` and `build/app.wasm` to `/apps/cf/`, for example over WebDAV (`dav://<device>/dav/apps/cf/`). Then send `/apps reload cf` in Telegram.

## Releases

Each release `v<version>` carries the signed package `cf-<version>.ecapp`, signed with the esp-claw key (key_id `7087d6a8`). It also carries the CI build it was made from (`app.wasm`, `manifest.json`). Install a release with:

```
/app install https://github.com/esp-claw/app-cloudflare/releases/download/v<version>/cf-<version>.ecapp
```

Maintainers: bump `version` in `manifest.json` and publish a release tagged `v<version>`. CI attaches the build. Then sign it locally and upload the `.ecapp`, as described in the [app-sdk release steps](https://github.com/esp-claw/app-sdk#releasing-an-app).

## Status

Runtime v1 in [esp-claw/esp-claw](https://github.com/esp-claw/esp-claw). The app passes a host harness (WAMR with mocked host functions and hand-written API fixtures) but has not run on a device yet.

Not verified against the live API:
- `cf_analytics` uses `httpRequests1hGroups` with a `datetime_geq` filter of type `Time`. How far back the data goes depends on the plan.
- `cf_tunnels` takes the data centers from `connections[].colo_name` in the `cfd_tunnel` list response.

Part of [esp-claw (community)](https://github.com/esp-claw), an unofficial community fork of espressif/esp-claw. It is not affiliated with Espressif.

## License

Apache-2.0
