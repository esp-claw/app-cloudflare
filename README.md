# app-cf-dns

esp-claw WASM app: read Cloudflare zones and DNS records through the device's credential profile.

Provides the tools `cf_dns_zones` and `cf_dns_records(zone)`. The app never sees the API token: the firmware adds it through the `cloudflare` credential profile. Read-only for now.

## Build

```sh
git clone --recursive https://github.com/esp-claw/app-cf-dns.git
cd app-cf-dns && ./sdk/build-app.sh .
```

This needs clang with the wasm32 target and wasm-ld (on Debian/Ubuntu: `apt install clang lld`). The output is `build/app.wasm` and `build/manifest.json`. CI builds every push and attaches both files to releases.

## Install

Copy both files to `/apps/cf_dns/` on the device, for example over WebDAV (`dav://<device>/dav/apps/cf_dns/`). Then send `/apps reload cf_dns` in Telegram, or restart the device.

**Status:** works with runtime v1 in [esp-claw/esp-claw](https://github.com/esp-claw/esp-claw). Packages are not signed yet; signing arrives with the installer.

Part of [esp-claw (community)](https://github.com/esp-claw), an unofficial community fork of espressif/esp-claw that is not affiliated with Espressif.

## License

Apache-2.0
