# app-cf-dns

esp-claw WASM app: read Cloudflare zones and DNS records through the device's credential profile.

Provides the tools `cf_dns_zones` and `cf_dns_records(zone)`. The app never sees the API token: the firmware adds it through the `cloudflare` credential profile. Read-only for now.

**Status:** in development. The code will be published here once the esp-claw WASM app runtime has been tested on hardware.

Part of [esp-claw (community)](https://github.com/esp-claw), an unofficial community fork of espressif/esp-claw that is not affiliated with Espressif.

## License

Apache-2.0
