/*
 * SPDX-FileCopyrightText: 2026 esp-claw contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
/*
 * cf: Cloudflare through the device's "cloudflare" API profile (account-owned API token).
 *   cf_zones       zones of the account (+ optional account/token check)
 *   cf_dns_list    DNS records of a zone, optional type/name filter
 *   cf_dns_upsert  create or update a DNS record (mutation: confirmed in Telegram by the device)
 *   cf_dns_delete  delete a DNS record by id or name+type (mutation)
 *   cf_purge       purge cached URLs or everything (mutation)
 *   cf_tunnels     Cloudflare Tunnels with status and connections
 *   cf_tunnel_create  create a remotely managed tunnel (+ optional private network route) (mutation)
 *   cf_tunnel_route   list, add or remove a tunnel's private network / hostname routes (mutation)
 *   cf_tunnel_delete  delete a tunnel without connections or routes (mutation)
 *   cf_workers     Workers scripts
 *   cf_analytics   HTTP traffic of a zone (GraphQL POST: the device asks for confirmation)
 * The device injects the API token; the app never sees it. Outputs are compact column/row JSON.
 */
#define CLAW_ARENA_SIZE 4096
#include "claw.h"
#include "claw_util.h"

CLAW_DEFINE_ARENA()

#define PROFILE     "cloudflare"
#define OUT_RESERVE 128 /* kept free while writing rows, for the closing text */

static int32_t s_t_zones = -1, s_t_list = -1, s_t_upsert = -1, s_t_delete = -1;
static int32_t s_t_purge = -1, s_t_tunnels = -1, s_t_workers = -1, s_t_analytics = -1;
static int32_t s_t_tun_create = -1, s_t_tun_route = -1, s_t_tun_delete = -1;

static char s_resp[32 * 1024 + 1];
static uint32_t s_resp_len;
static char s_out[16 * 1024];
static claw_buf_t s_b;
static uint32_t s_mark;
static int s_trunc;
static char s_path[1024];
static claw_buf_t s_p;
static char s_body[4096];
static const char *s_args, *s_args_end;
static char s_acct[40];
static char s_zone_id[40];
static char s_zone[256];

/* ---------- small helpers (no libc) ---------- */

static int str_eq(const char *a, uint32_t an, const char *b)
{
    uint32_t i = 0;

    for (; i < an && b[i] && a[i] == b[i]; i++) {
    }
    return i == an && !b[i];
}

static int ends_with(const char *s, uint32_t n, const char *suffix, uint32_t sn)
{
    if (sn > n) {
        return 0;
    }
    for (uint32_t i = 0; i < sn; i++) {
        if (s[n - sn + i] != suffix[i]) {
            return 0;
        }
    }
    return 1;
}

static int is_hex32(const char *s, int32_t n)
{
    if (n != 32) {
        return 0;
    }
    for (int32_t i = 0; i < n; i++) {
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f'))) {
            return 0;
        }
    }
    return 1;
}

/* Host-name-ish characters only (zone/record names), so values cannot inject query syntax. */
static int is_name(char *s, int32_t n, int allow_wild)
{
    if (n <= 0) {
        return 0;
    }
    for (int32_t i = 0; i < n; i++) {
        char c = s[i];

        if (c >= 'A' && c <= 'Z') {
            s[i] = (char)(c + 32);
        } else if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_' ||
                     (allow_wild && (c == '*' || c == '@')))) {
            return 0;
        }
    }
    return 1;
}

/* ---------- output ---------- */

/* Out of line: the SDK helpers are static inline and would otherwise be inlined at every call. */
#define NOINLINE __attribute__((noinline))

static NOINLINE void P(const char *s)
{
    cb_put(&s_b, s);
}

static NOINLINE void bput(claw_buf_t *b, const char *s)
{
    cb_put(b, s);
}

static NOINLINE void bput_u32(claw_buf_t *b, uint32_t v)
{
    cb_put_u32(b, v);
}

static void out_begin(void)
{
    s_b.buf = s_out;
    s_b.cap = sizeof(s_out) - OUT_RESERVE;
    s_b.len = 0;
    s_b.full = 0;
    s_out[0] = '\0';
    s_trunc = 0;
}

static void out_end(void)
{
    s_b.cap = sizeof(s_out);
    claw_tool_result(s_b.buf, s_b.len);
}

static void row_begin(void)
{
    s_mark = s_b.len;
}

/* Rolls back a row that did not fit; returns 0 then (stop adding rows). */
static int row_end(void)
{
    if (!s_b.full) {
        return 1;
    }
    s_b.len = s_mark;
    s_b.buf[s_mark] = '\0';
    s_b.full = 0;
    s_trunc = 1;
    return 0;
}

static NOINLINE void put_u64(uint64_t v)
{
    char tmp[20];
    char out[20];
    int n = 0;
    int i = 0;

    do {
        tmp[n++] = (char)('0' + v % 10);
        v /= 10;
    } while (v);
    while (n) {
        out[i++] = tmp[--n];
    }
    cb_putn(&s_b, out, (uint32_t)i);
}

static void put_i32(int32_t v)
{
    if (v < 0) {
        P("-");
        v = -v;
    }
    bput_u32(&s_b, (uint32_t)v);
}

/* Appends text from [p, e) as JSON string contents, at most `max` source bytes, cut at a character
 * boundary. Flags: SAFE_JSON = the text is already JSON-escaped (escape sequences are copied whole),
 * otherwise quotes/backslashes are escaped and control bytes/ANSI sequences dropped; SAFE_CUT = cut
 * silently (dates), else "..." marks a cut. Invalid UTF-8 bytes are dropped in all modes. */
#define SAFE_JSON 1
#define SAFE_CUT  2

static NOINLINE void put_safe(const char *p, const char *e, uint32_t max, int flags)
{
    uint32_t used = 0;
    int json = flags & SAFE_JSON;

    while (p < e) {
        unsigned char c = (unsigned char)*p;
        uint32_t unit = 1;

        if (json && c == '\\') {
            unit = p + 1 < e && p[1] == 'u' ? 6 : 2;
            if (unit == 6 && p + 12 <= e && (p[2] == 'd' || p[2] == 'D') &&
                    (p[3] == '8' || p[3] == '9' || p[3] == 'a' || p[3] == 'b' || p[3] == 'A' || p[3] == 'B')) {
                unit = 12; /* surrogate pair stays together */
            }
            if (p + unit > e) {
                break;
            }
        } else if (c >= 0x80) {
            unsigned char c1 = p + 1 < e ? (unsigned char)p[1] : 0;
            int ok = 1;

            unit = c >= 0xc2 && c <= 0xdf ? 2 : c >= 0xe0 && c <= 0xef ? 3 : c >= 0xf0 && c <= 0xf4 ? 4 : 0;
            if (!unit || p + unit > e || (c == 0xe0 && c1 < 0xa0) || (c == 0xed && c1 > 0x9f) ||
                    (c == 0xf0 && c1 < 0x90) || (c == 0xf4 && c1 > 0x8f)) {
                ok = 0;
            }
            for (uint32_t i = 1; ok && i < unit; i++) {
                ok = ((unsigned char)p[i] & 0xc0) == 0x80;
            }
            if (!ok) {
                p++;
                continue;
            }
        } else if (!json && c == 0x1b) {
            p++;
            if (p < e && *p == '[') {
                for (p++; p < e && !(*p >= 0x40 && *p <= 0x7e); p++) {
                }
                p += p < e;
            }
            continue;
        } else if (!json && (c < 0x20 || c == 0x7f)) {
            if (c == '\t') {
                cb_putn(&s_b, " ", 1);
                used++;
            }
            p++;
            continue;
        }
        if (used + unit > max) {
            if (!(flags & SAFE_CUT)) {
                P("...");
            }
            return;
        }
        if (!json && (c == '"' || c == '\\')) {
            cb_putn(&s_b, "\\", 1);
        }
        cb_putn(&s_b, p, unit);
        used += unit;
        p += unit;
    }
}

/* The JSON string at v as a quoted string trimmed to `max` bytes; null for anything else. */
static NOINLINE void put_jstr(const char *v, const char *end, uint32_t max)
{
    const char *close;

    if (!v || v >= end || *v != '"' || !(close = cj_skip(v, end))) {
        P("null");
        return;
    }
    P("\"");
    put_safe(v + 1, close - 1, max, SAFE_JSON);
    P("\"");
}

/* The JSON string at v cut to `max` bytes without a marker (timestamps: 16 = minutes, 10 = date). */
static NOINLINE void put_jcut(const char *v, const char *end, uint32_t max)
{
    const char *close;

    if (!v || v >= end || *v != '"' || !(close = cj_skip(v, end))) {
        P("null");
        return;
    }
    P("\"");
    put_safe(v + 1, close - 1, max, SAFE_JSON | SAFE_CUT);
    P("\"");
}

/* A scalar (number, true/false/null) copied as-is; strings trimmed; objects/arrays become null. */
static NOINLINE void put_raw(const char *v, const char *end)
{
    const char *e;

    if (v && v < end && *v == '"') {
        put_jstr(v, end, 200);
    } else if (!v || v >= end || *v == '{' || *v == '[' || !(e = cj_skip(v, end)) || e - v > 24) {
        P("null");
    } else {
        cb_putn(&s_b, v, (uint32_t)(e - v));
    }
}

static const char *mem(const char *obj, const char *end, const char *k1, const char *k2)
{
    const char *v = cj_member(obj, end, k1);

    return k2 && v ? cj_member(v, end, k2) : v;
}

static NOINLINE void err_result(const char *msg, const char *detail)
{
    out_begin();
    P("{\"error\":\"");
    P(msg);
    if (detail) {
        P("\",\"value\":\"");
        put_safe(detail, detail + claw_strlen(detail), 200, 0);
    }
    P("\"}");
    out_end();
}

/* ---------- args ---------- */

static int32_t arg_str(const char *key, char *out, uint32_t cap)
{
    return cj_string(cj_member(s_args, s_args_end, key), s_args_end, out, cap);
}

static int64_t arg_int(const char *key, int64_t def)
{
    const char *v = cj_member(s_args, s_args_end, key);
    int64_t n;

    if (v && *v == '"') {
        v++;
    }
    n = v ? cj_uint(v, s_args_end) : -1;
    return n < 0 ? def : n;
}

/* 1 / 0, or -1 when absent or not a boolean. */
static int arg_bool(const char *key)
{
    const char *v = cj_member(s_args, s_args_end, key);

    if (v && *v == '"') {
        v++;
    }
    if (v && s_args_end - v >= 4 && v[0] == 't' && v[1] == 'r' && v[2] == 'u' && v[3] == 'e') {
        return 1;
    }
    if (v && s_args_end - v >= 5 && v[0] == 'f' && v[1] == 'a' && v[2] == 'l' && v[3] == 's' && v[4] == 'e') {
        return 0;
    }
    return -1;
}

/* ---------- HTTP ---------- */

static void path_begin(const char *s)
{
    s_p.buf = s_path;
    s_p.cap = sizeof(s_path);
    s_p.len = 0;
    s_p.full = 0;
    bput(&s_p, s);
}

static NOINLINE int32_t http(const char *method, const char *body, uint32_t body_len)
{
    int32_t rc;
    int32_t n;

    if (s_p.full) {
        s_resp_len = 0;
        return -CLAW_E2BIG;
    }
    rc = claw_http_profile_request(CLAW_S(PROFILE), CLAW_S(method), s_p.buf, s_p.len, "", 0, body, body_len);
    s_resp_len = 0;
    while (s_resp_len < sizeof(s_resp) - 1 &&
            (n = claw_http_response_read(s_resp + s_resp_len, sizeof(s_resp) - 1 - s_resp_len)) > 0) {
        s_resp_len += (uint32_t)n;
    }
    s_resp[s_resp_len] = '\0';
    return rc;
}

static int32_t get(void)
{
    return http("GET", "", 0);
}

/* Reports a failed request: Cloudflare's errors[] (or GraphQL errors), else the device's text. */
static NOINLINE void fail(const char *what, int32_t rc)
{
    const char *end = s_resp + s_resp_len;
    const char *errs = cj_member(s_resp, end, "errors");
    const char *e = cj_first(errs, end);

    out_begin();
    P("{\"error\":\"");
    P(what);
    P(" failed\",\"status\":");
    put_i32(rc);
    if (e) {
        P(",\"errors\":[");
        for (int i = 0; e && i < 4; e = cj_next(e, end), i++) {
            P(i ? ",\"" : "\"");
            if (cj_member(e, end, "code")) {
                put_raw(cj_member(e, end, "code"), end);
                P(": ");
            }
            {
                const char *m = cj_member(e, end, "message");
                const char *close = m && *m == '"' ? cj_skip(m, end) : 0;

                if (close) {
                    put_safe(m + 1, close - 1, 200, SAFE_JSON);
                }
            }
            P("\"");
        }
        P("]");
    } else if (s_resp_len) {
        P(",\"detail\":\"");
        put_safe(s_resp, end, 300, 0);
        P("\"");
    }
    if (rc == 401 || rc == 403) {
        P(",\"hint\":\"token lacks a permission for this resource (code 10000) or is invalid\"");
    }
    P("}");
    out_end();
}

/* ---------- account and zone resolution ---------- */

/* Account id from kv, else GET /accounts (first account) and cache it. 1 = ok, else result set. */
static int account(void)
{
    const char *end;
    int32_t n = claw_kv_get(CLAW_S("acct"), s_acct, sizeof(s_acct) - 1);
    int32_t rc;

    if (n > 0) {
        s_acct[n] = '\0';
        return 1;
    }
    path_begin("/accounts?per_page=5");
    rc = get();
    end = s_resp + s_resp_len;
    if (rc != 200) {
        fail("GET /accounts", rc);
        return 0;
    }
    n = cj_string(mem(cj_first(cj_member(s_resp, end, "result"), end), end, "id", 0), end, s_acct, sizeof(s_acct));
    if (!is_hex32(s_acct, n)) {
        err_result("no account visible to the token", 0);
        return 0;
    }
    claw_kv_set(CLAW_S("acct"), s_acct, (uint32_t)n);
    return 1;
}

/* Drops a cached account id that the API no longer accepts. */
static void account_check(int32_t rc)
{
    if (rc == 403 || rc == 404) {
        claw_kv_del(CLAW_S("acct"));
    }
}

/* Resolves args.zone (name or 32-hex id) into s_zone_id and s_zone (name). 1 = ok, else result set. */
static int zone(void)
{
    const char *end;
    const char *z;
    int32_t n = arg_str("zone", s_zone, sizeof(s_zone));
    int32_t rc;

    if (is_hex32(s_zone, n)) {
        path_begin("/zones/");
        bput(&s_p, s_zone);
    } else if (is_name(s_zone, n, 0)) {
        path_begin("/zones?per_page=1&name=");
        bput(&s_p, s_zone);
    } else {
        err_result("zone must be a domain name or zone id", 0);
        return 0;
    }
    rc = get();
    end = s_resp + s_resp_len;
    if (rc != 200 && rc != 404) {
        fail("zone lookup", rc);
        return 0;
    }
    z = cj_member(s_resp, end, "result");
    if (z && *z == '[') {
        z = cj_first(z, end);
    }
    if (rc != 200 || cj_string(cj_member(z, end, "id"), end, s_zone_id, sizeof(s_zone_id)) != 32 ||
            cj_string(cj_member(z, end, "name"), end, s_zone, sizeof(s_zone)) <= 0) {
        err_result("zone not found", s_zone);
        return 0;
    }
    return 1;
}

/* Full record name from a short one: "@"/"" = apex, "www" = www.<zone>, FQDNs kept. */
static int full_name(char *out, uint32_t cap)
{
    int32_t n = arg_str("name", out, cap);
    uint32_t zl = claw_strlen(s_zone);

    if (n > 0 && out[n - 1] == '.') {
        out[--n] = '\0';
    }
    if (n <= 0 || (n == 1 && out[0] == '@')) {
        if (zl + 1 > cap) {
            return 0;
        }
        for (uint32_t i = 0; i <= zl; i++) {
            out[i] = s_zone[i];
        }
        return 1;
    }
    if (!is_name(out, n, 1)) {
        return 0;
    }
    if (!str_eq(out, (uint32_t)n, s_zone) &&
            !(ends_with(out, (uint32_t)n, s_zone, zl) && (uint32_t)n > zl && out[n - zl - 1] == '.')) {
        if ((uint32_t)n + 1 + zl + 1 > cap) {
            return 0;
        }
        out[n++] = '.';
        for (uint32_t i = 0; i <= zl; i++) {
            out[n + i] = s_zone[i];
        }
    }
    return 1;
}

/* The record name relative to the zone ("@" for the apex). */
static NOINLINE void put_short_name(const char *v, const char *end)
{
    char name[256];
    int32_t n = cj_string(v, end, name, sizeof(name));
    uint32_t zl = claw_strlen(s_zone);

    if (n < 0) {
        P("null");
    } else if (str_eq(name, (uint32_t)n, s_zone)) {
        P("\"@\"");
    } else {
        if ((uint32_t)n > zl + 1 && ends_with(name, (uint32_t)n, s_zone, zl) && name[n - zl - 1] == '.') {
            n -= (int32_t)zl + 1;
        }
        P("\"");
        cb_putn(&s_b, name, (uint32_t)n);
        P("\"");
    }
}

/* [name, type, content, ttl, proxied, id] of a DNS record object. */
static NOINLINE void put_record(const char *r, const char *end)
{
    P("[");
    put_short_name(cj_member(r, end, "name"), end);
    P(",");
    put_jstr(cj_member(r, end, "type"), end, 12);
    P(",");
    put_jstr(cj_member(r, end, "content"), end, 200);
    P(",");
    put_raw(cj_member(r, end, "ttl"), end);
    P(",");
    put_raw(cj_member(r, end, "proxied"), end);
    P(",");
    put_jstr(cj_member(r, end, "id"), end, 40);
    P("]");
}

#define RECORD_COLS "[\"name\",\"type\",\"content\",\"ttl\",\"proxied\",\"id\"]"

/* Lists matching records (GET .../dns_records?type=&name=) into s_resp; returns the HTTP status. */
static int32_t find_records(const char *type, const char *fqdn, uint32_t per_page)
{
    path_begin("/zones/");
    bput(&s_p, s_zone_id);
    bput(&s_p, "/dns_records?per_page=");
    bput_u32(&s_p, per_page);
    if (type && type[0]) {
        bput(&s_p, "&type=");
        bput(&s_p, type);
    }
    if (fqdn && fqdn[0]) {
        bput(&s_p, "&name=");
        bput(&s_p, fqdn);
    }
    return get();
}

static int valid_type(char *t, int32_t n)
{
    if (n <= 0 || n > 10) {
        return 0;
    }
    for (int32_t i = 0; i < n; i++) {
        if (t[i] >= 'a' && t[i] <= 'z') {
            t[i] = (char)(t[i] - 32);
        } else if (!((t[i] >= 'A' && t[i] <= 'Z') || (t[i] >= '0' && t[i] <= '9'))) {
            return 0;
        }
    }
    return 1;
}

/* ---------- tools ---------- */

static void tool_zones(void)
{
    const char *end;
    int32_t rc;
    char tok[24] = "";
    int verify = arg_bool("verify") == 1;

    if (verify) {
        if (!account()) {
            return;
        }
        path_begin("/accounts/");
        bput(&s_p, s_acct);
        bput(&s_p, "/tokens/verify");
        rc = get();
        end = s_resp + s_resp_len;
        if (rc != 200) {
            account_check(rc);
            fail("token verify", rc);
            return;
        }
        cj_string(mem(s_resp, end, "result", "status"), end, tok, sizeof(tok));
    }
    path_begin("/zones?per_page=50");
    rc = get();
    end = s_resp + s_resp_len;
    if (rc != 200) {
        fail("GET /zones", rc);
        return;
    }
    out_begin();
    if (verify) {
        P("{\"account\":\"");
        P(s_acct);
        P("\",\"token\":\"");
        P(tok);
        P("\",");
    } else {
        P("{");
    }
    P("\"cols\":[\"name\",\"status\",\"plan\",\"id\"],\"rows\":[");
    {
        uint32_t n = 0;

        for (const char *z = cj_first(cj_member(s_resp, end, "result"), end); z; z = cj_next(z, end)) {
            if (!cj_skip(z, end)) {
                s_trunc = 1;
                break;
            }
            row_begin();
            P(n ? ",[" : "[");
            put_jstr(cj_member(z, end, "name"), end, 120);
            P(",");
            put_jstr(cj_member(z, end, "status"), end, 20);
            P(",");
            put_jstr(mem(z, end, "plan", "name"), end, 40);
            P(",");
            put_jstr(cj_member(z, end, "id"), end, 40);
            P("]");
            if (!row_end()) {
                break;
            }
            n++;
        }
        s_b.cap = sizeof(s_out);
        P("],\"count\":");
        bput_u32(&s_b, n);
        P(",\"total\":");
        put_raw(mem(s_resp, end, "result_info", "total_count"), end);
    }
    P(s_trunc ? ",\"truncated\":true}" : "}");
    out_end();
}

static void tool_dns_list(void)
{
    char type[16];
    char fqdn[300] = "";
    int32_t tn = arg_str("type", type, sizeof(type));
    int has_name = cj_member(s_args, s_args_end, "name") != 0;
    uint32_t count = 0;
    int64_t pages = 1;

    if (!zone()) {
        return;
    }
    if (tn > 0 && !valid_type(type, tn)) {
        err_result("type must be a record type like A, AAAA, CNAME, TXT, MX", 0);
        return;
    }
    if (tn <= 0) {
        type[0] = '\0';
    }
    if (has_name && !full_name(fqdn, sizeof(fqdn))) {
        err_result("name must be a host name, relative to the zone or fully qualified", 0);
        return;
    }
    out_begin();
    P("{\"zone\":\"");
    P(s_zone);
    P("\",\"cols\":" RECORD_COLS ",\"rows\":[");
    for (int64_t page = 1; page <= pages && page <= 5 && !s_trunc; page++) {
        const char *end;
        int32_t rc;

        path_begin("/zones/");
        bput(&s_p, s_zone_id);
        bput(&s_p, "/dns_records?per_page=50&page=");
        bput_u32(&s_p, (uint32_t)page);
        if (type[0]) {
            bput(&s_p, "&type=");
            bput(&s_p, type);
        }
        if (fqdn[0]) {
            bput(&s_p, "&name=");
            bput(&s_p, fqdn);
        }
        rc = get();
        if (rc != 200) {
            fail("GET dns_records", rc);
            return;
        }
        end = s_resp + s_resp_len;
        pages = cj_uint(mem(s_resp, end, "result_info", "total_pages"), end);
        for (const char *r = cj_first(cj_member(s_resp, end, "result"), end); r; r = cj_next(r, end)) {
            if (!cj_skip(r, end)) {
                s_trunc = 1;
                break;
            }
            row_begin();
            P(count ? "," : "");
            put_record(r, end);
            if (!row_end()) {
                break;
            }
            count++;
        }
    }
    s_b.cap = sizeof(s_out);
    P("],\"count\":");
    bput_u32(&s_b, count);
    P(",\"ttl_1\":\"auto\"");
    P(s_trunc || pages > 5 ? ",\"truncated\":true}" : "}");
    out_end();
}

static void tool_dns_upsert(void)
{
    static char content[2048];
    char type[16];
    char fqdn[300];
    char rid[40];
    static char cur[2048];
    int32_t tn = arg_str("type", type, sizeof(type));
    int32_t cn = arg_str("content", content, sizeof(content));
    int32_t idn = arg_str("record_id", rid, sizeof(rid));
    int64_t ttl = arg_int("ttl", -1);
    int proxied = arg_bool("proxied");
    const char *end;
    const char *r = 0;
    claw_buf_t body = { s_body, sizeof(s_body), 0, 0 };
    int32_t rc;

    if (!zone()) {
        return;
    }
    if (!valid_type(type, tn)) {
        err_result("type is required (A, AAAA, CNAME, TXT, MX, ...)", 0);
        return;
    }
    if (cn <= 0) {
        err_result("content is required (max 2047 bytes)", 0);
        return;
    }
    if (!cj_member(s_args, s_args_end, "name") || !full_name(fqdn, sizeof(fqdn))) {
        err_result("name is required: www, @ (apex) or a full name in the zone", 0);
        return;
    }
    if (idn > 0 && !is_hex32(rid, idn)) {
        err_result("record_id must be a 32-char hex id from cf_dns_list", 0);
        return;
    }
    if (ttl != -1 && ttl != 1 && (ttl < 30 || ttl > 86400)) {
        err_result("ttl must be 1 (auto) or 30-86400", 0);
        return;
    }

    /* Find the record to update: by id, else the single record with this name and type. */
    if (idn > 0) {
        path_begin("/zones/");
        bput(&s_p, s_zone_id);
        bput(&s_p, "/dns_records/");
        bput(&s_p, rid);
        rc = get();
        end = s_resp + s_resp_len;
        if (rc != 200) {
            fail("GET dns record", rc);
            return;
        }
        r = cj_member(s_resp, end, "result");
    } else {
        uint32_t matches = 0;

        rc = find_records(type, fqdn, 10);
        end = s_resp + s_resp_len;
        if (rc != 200) {
            fail("GET dns_records", rc);
            return;
        }
        for (const char *it = cj_first(cj_member(s_resp, end, "result"), end); it; it = cj_next(it, end)) {
            r = it;
            matches++;
        }
        if (matches > 1) {
            out_begin();
            P("{\"error\":\"several records match; pass record_id\",\"cols\":" RECORD_COLS ",\"rows\":[");
            matches = 0;
            for (const char *it = cj_first(cj_member(s_resp, end, "result"), end); it; it = cj_next(it, end)) {
                P(matches++ ? "," : "");
                put_record(it, end);
            }
            s_b.cap = sizeof(s_out);
            P("]}");
            out_end();
            return;
        }
    }

    if (r && cj_string(cj_member(r, end, "id"), end, rid, sizeof(rid)) == 32) {
        const char *t = cj_member(r, end, "ttl");
        const char *px = cj_member(r, end, "proxied");
        int32_t curn = cj_string(cj_member(r, end, "content"), end, cur, sizeof(cur));

        if (curn == cn && str_eq(cur, (uint32_t)curn, content) && (ttl < 0 || cj_uint(t, end) == ttl) &&
                (proxied < 0 || (px && *px == (proxied ? 't' : 'f')))) {
            out_begin();
            P("{\"ok\":true,\"action\":\"unchanged\",\"cols\":" RECORD_COLS ",\"record\":");
            put_record(r, end);
            P("}");
            out_end();
            return;
        }
    } else {
        idn = 0;
        rid[0] = '\0';
    }

    bput(&body, "{\"type\":\"");
    bput(&body, type);
    bput(&body, "\",\"name\":\"");
    bput(&body, fqdn);
    bput(&body, "\",\"content\":\"");
    bput(&body, content); /* still JSON-escaped from the arguments */
    bput(&body, "\"");
    if (ttl > 0 || !rid[0]) {
        bput(&body, ",\"ttl\":");
        bput_u32(&body, ttl > 0 ? (uint32_t)ttl : 1);
    }
    if (proxied >= 0) {
        bput(&body, proxied ? ",\"proxied\":true" : ",\"proxied\":false");
    }
    bput(&body, "}");
    if (body.full) {
        err_result("record too large", 0);
        return;
    }
    path_begin("/zones/");
    bput(&s_p, s_zone_id);
    bput(&s_p, "/dns_records");
    if (rid[0]) {
        bput(&s_p, "/");
        bput(&s_p, rid);
    }
    rc = http(rid[0] ? "PATCH" : "POST", body.buf, body.len);
    end = s_resp + s_resp_len;
    if (rc != 200) {
        fail(rid[0] ? "PATCH dns record" : "POST dns record", rc);
        return;
    }
    out_begin();
    P(rid[0] ? "{\"ok\":true,\"action\":\"updated\"" : "{\"ok\":true,\"action\":\"created\"");
    P(",\"cols\":" RECORD_COLS ",\"record\":");
    put_record(cj_member(s_resp, end, "result"), end);
    P("}");
    out_end();
}

static void tool_dns_delete(void)
{
    char type[16];
    char fqdn[300];
    char rid[40];
    int32_t tn = arg_str("type", type, sizeof(type));
    int32_t idn = arg_str("record_id", rid, sizeof(rid));
    const char *end;
    const char *r = 0;
    int32_t rc;
    char before[1024];
    claw_buf_t saved;

    if (!zone()) {
        return;
    }
    if (idn > 0) {
        if (!is_hex32(rid, idn)) {
            err_result("record_id must be a 32-char hex id from cf_dns_list", 0);
            return;
        }
        path_begin("/zones/");
        bput(&s_p, s_zone_id);
        bput(&s_p, "/dns_records/");
        bput(&s_p, rid);
        rc = get();
        end = s_resp + s_resp_len;
        if (rc != 200) {
            fail("GET dns record", rc);
            return;
        }
        r = cj_member(s_resp, end, "result");
    } else {
        uint32_t matches = 0;

        if (!valid_type(type, tn) || !cj_member(s_args, s_args_end, "name") || !full_name(fqdn, sizeof(fqdn))) {
            err_result("pass record_id, or name and type", 0);
            return;
        }
        rc = find_records(type, fqdn, 10);
        end = s_resp + s_resp_len;
        if (rc != 200) {
            fail("GET dns_records", rc);
            return;
        }
        for (const char *it = cj_first(cj_member(s_resp, end, "result"), end); it; it = cj_next(it, end)) {
            r = it;
            matches++;
        }
        if (matches != 1) {
            out_begin();
            P(matches ? "{\"error\":\"several records match; pass record_id\",\"cols\":" RECORD_COLS ",\"rows\":["
              : "{\"error\":\"no such record\",\"rows\":[");
            matches = 0;
            for (const char *it = cj_first(cj_member(s_resp, end, "result"), end); it; it = cj_next(it, end)) {
                P(matches++ ? "," : "");
                put_record(it, end);
            }
            s_b.cap = sizeof(s_out);
            P("]}");
            out_end();
            return;
        }
        if (cj_string(cj_member(r, end, "id"), end, rid, sizeof(rid)) != 32) {
            err_result("record without id", 0);
            return;
        }
    }

    /* Keep the record's description for the result; s_resp is reused by the DELETE. */
    out_begin();
    saved = s_b;
    s_b.buf = before;
    s_b.cap = sizeof(before);
    s_b.len = 0;
    put_record(r, end);
    {
        uint32_t blen = s_b.full ? 0 : s_b.len;

        s_b = saved;
        path_begin("/zones/");
        bput(&s_p, s_zone_id);
        bput(&s_p, "/dns_records/");
        bput(&s_p, rid);
        rc = http("DELETE", "", 0);
        if (rc != 200) {
            fail("DELETE dns record", rc);
            return;
        }
        out_begin();
        P("{\"ok\":true,\"action\":\"deleted\",\"cols\":" RECORD_COLS ",\"record\":");
        if (blen) {
            cb_putn(&s_b, before, blen);
        } else {
            P("null");
        }
        P("}");
        out_end();
    }
}

static void tool_purge(void)
{
    const char *urls = cj_member(s_args, s_args_end, "urls");
    int everything = arg_bool("everything") == 1;
    claw_buf_t body = { s_body, sizeof(s_body), 0, 0 };
    uint32_t n = 0;
    int32_t rc;

    if (!zone()) {
        return;
    }
    if (everything == (cj_first(urls, s_args_end) != 0)) {
        err_result("pass either urls (list of full URLs) or everything=true", 0);
        return;
    }
    if (everything) {
        bput(&body, "{\"purge_everything\":true}");
    } else {
        bput(&body, "{\"files\":[");
        for (const char *u = cj_first(urls, s_args_end); u; u = cj_next(u, s_args_end)) {
            char url[1024];
            int32_t ul = cj_string(u, s_args_end, url, sizeof(url));

            if (ul < 9 || n >= 30 || !(url[0] == 'h' && url[1] == 't' && url[2] == 't' && url[3] == 'p')) {
                err_result("urls must be up to 30 full http(s) URLs", ul > 0 ? url : 0);
                return;
            }
            bput(&body, n++ ? ",\"" : "\"");
            bput(&body, url);
            bput(&body, "\"");
        }
        bput(&body, "]}");
    }
    if (body.full) {
        err_result("too many URLs", 0);
        return;
    }
    path_begin("/zones/");
    bput(&s_p, s_zone_id);
    bput(&s_p, "/purge_cache");
    rc = http("POST", body.buf, body.len);
    if (rc != 200) {
        fail("POST purge_cache", rc);
        return;
    }
    out_begin();
    P("{\"ok\":true,\"zone\":\"");
    P(s_zone);
    P("\",\"purged\":");
    if (everything) {
        P("\"everything\"");
    } else {
        bput_u32(&s_b, n);
    }
    P("}");
    out_end();
}

static void tool_tunnels(void)
{
    uint32_t count = 0;
    int64_t pages = 1;

    if (!account()) {
        return;
    }
    out_begin();
    P("{\"cols\":[\"name\",\"status\",\"conns\",\"colos\",\"since\",\"id\"],\"rows\":[");
    for (int64_t page = 1; page <= pages && page <= 4 && !s_trunc; page++) {
        const char *end;
        int32_t rc;

        path_begin("/accounts/");
        bput(&s_p, s_acct);
        bput(&s_p, "/cfd_tunnel?is_deleted=false&per_page=20&page=");
        bput_u32(&s_p, (uint32_t)page);
        rc = get();
        if (rc != 200) {
            account_check(rc);
            fail("GET cfd_tunnel", rc);
            return;
        }
        end = s_resp + s_resp_len;
        pages = cj_uint(mem(s_resp, end, "result_info", "total_pages"), end);
        for (const char *t = cj_first(cj_member(s_resp, end, "result"), end); t; t = cj_next(t, end)) {
            const char *conns = cj_member(t, end, "connections");
            char status[16] = "";
            uint32_t nc = 0;
            int32_t n;
            int healthy;

            if (!cj_skip(t, end)) {
                s_trunc = 1;
                break;
            }
            n = cj_string(cj_member(t, end, "status"), end, status, sizeof(status));
            healthy = n > 0 && (str_eq(status, (uint32_t)n, "healthy") || str_eq(status, (uint32_t)n, "degraded"));
            row_begin();
            P(count ? ",[" : "[");
            put_jstr(cj_member(t, end, "name"), end, 80);
            P(",\"");
            P(status);
            P("\",");
            for (const char *c = cj_first(conns, end); c; c = cj_next(c, end)) {
                nc++;
            }
            bput_u32(&s_b, nc);
            P(",\"");
            /* distinct data center codes of the connections, e.g. "fra06 ams01" (connections[].colo_name,
             * UNVERIFIED on the live API) */
            {
                char seen[8][16];
                uint32_t ns = 0;

                for (const char *c = cj_first(conns, end); c && ns < 8; c = cj_next(c, end)) {
                    char colo[16];
                    int32_t cl = cj_string(cj_member(c, end, "colo_name"), end, colo, sizeof(colo));
                    uint32_t k = 0;

                    for (; cl > 0 && k < ns && !str_eq(colo, (uint32_t)cl, seen[k]); k++) {
                    }
                    if (cl > 0 && k == ns) {
                        for (int32_t i = 0; i <= cl; i++) {
                            seen[ns][i] = colo[i];
                        }
                        P(ns++ ? " " : "");
                        put_safe(colo, colo + cl, 16, SAFE_JSON);
                    }
                }
            }
            P("\",");
            put_jcut(cj_member(t, end, healthy ? "conns_active_at" : "conns_inactive_at"), end, 16);
            P(",");
            put_jstr(cj_member(t, end, "id"), end, 40);
            P("]");
            if (!row_end()) {
                break;
            }
            count++;
        }
    }
    s_b.cap = sizeof(s_out);
    P("],\"count\":");
    bput_u32(&s_b, count);
    P(s_trunc || pages > 4 ? ",\"truncated\":true}" : "}");
    out_end();
}

/* ---------- tunnel setup (the connector token is never fetched) ---------- */

static char s_tun_id[40];
static char s_tun_name[128];
static int s_tun_up;

static int is_uuid(const char *s, int32_t n)
{
    if (n != 36) {
        return 0;
    }
    for (int32_t i = 0; i < n; i++) {
        char c = s[i];

        if (i == 8 || i == 13 || i == 18 || i == 23 ? c != '-' :
                !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
            return 0;
        }
    }
    return 1;
}

/* Tunnel names as the app creates and looks them up: letters, digits, '.', '-', '_' (case kept). */
static int is_tunnel_name(const char *s, int32_t n)
{
    if (n <= 0) {
        return 0;
    }
    for (int32_t i = 0; i < n; i++) {
        char c = s[i];

        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' ||
                c == '-' || c == '_')) {
            return 0;
        }
    }
    return 1;
}

/* IPv4/IPv6 network in CIDR notation, by character set only; the API validates the rest. */
static int is_cidr(const char *s, int32_t n)
{
    int32_t slash = -1;

    for (int32_t i = 0; i < n; i++) {
        char c = s[i];

        if (c == '/') {
            if (slash >= 0) {
                return 0;
            }
            slash = i;
        } else if (slash >= 0 ? !(c >= '0' && c <= '9') :
                   !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == '.' ||
                     c == ':')) {
            return 0;
        }
    }
    return slash > 1 && n - slash >= 2 && n - slash <= 4;
}

/* Resolves args.tunnel (name or id) into s_tun_id, s_tun_name, s_tun_up. 1 = ok, else result set. */
static int tunnel(void)
{
    char t[64];
    int32_t n = arg_str("tunnel", t, sizeof(t));
    const char *end;
    const char *r;
    uint32_t matches = 0;
    int32_t rc;

    if (!account()) {
        return 0;
    }
    path_begin("/accounts/");
    bput(&s_p, s_acct);
    if (is_uuid(t, n)) {
        bput(&s_p, "/cfd_tunnel/");
        bput(&s_p, t);
    } else if (is_tunnel_name(t, n)) {
        bput(&s_p, "/cfd_tunnel?is_deleted=false&per_page=10&name=");
        bput(&s_p, t);
    } else {
        err_result("tunnel must be a tunnel name or id from cf_tunnels", 0);
        return 0;
    }
    rc = get();
    end = s_resp + s_resp_len;
    if (rc != 200 && rc != 404) {
        account_check(rc);
        fail("tunnel lookup", rc);
        return 0;
    }
    r = cj_member(s_resp, end, "result");
    if (r && *r == '[') {
        const char *hit = 0;

        for (const char *it = cj_first(r, end); it; it = cj_next(it, end)) {
            char nm[64];
            int32_t nl = cj_string(cj_member(it, end, "name"), end, nm, sizeof(nm));

            if (nl == n && str_eq(nm, (uint32_t)nl, t)) {
                hit = it;
                matches++;
            }
        }
        r = hit;
    }
    if (matches > 1) {
        err_result("several tunnels have this name; pass the id from cf_tunnels", t);
        return 0;
    }
    if (rc != 200 || cj_string(cj_member(r, end, "id"), end, s_tun_id, sizeof(s_tun_id)) != 36 ||
            cj_string(cj_member(r, end, "name"), end, s_tun_name, sizeof(s_tun_name)) <= 0) {
        err_result("tunnel not found", t);
        return 0;
    }
    {
        char status[16];

        n = cj_string(cj_member(r, end, "status"), end, status, sizeof(status));
        s_tun_up = n > 0 && (str_eq(status, (uint32_t)n, "healthy") || str_eq(status, (uint32_t)n, "degraded"));
    }
    return 1;
}

static void put_tun_name(void)
{
    P("\"");
    put_safe(s_tun_name, s_tun_name + claw_strlen(s_tun_name), 80, SAFE_JSON);
    P("\"");
}

#define ROUTE_COLS "[\"kind\",\"target\",\"comment\",\"id\"]"

/* GET of the tunnel's private network routes (hostname = 0) or hostname routes into s_resp. */
static int32_t get_routes(int hostname)
{
    path_begin("/accounts/");
    bput(&s_p, s_acct);
    bput(&s_p, hostname ? "/zerotrust/routes/hostname" : "/teamnet/routes");
    bput(&s_p, "?is_deleted=false&per_page=50&tunnel_id=");
    bput(&s_p, s_tun_id);
    return get();
}

/* Appends both kinds of routes of the tunnel as rows; returns their number, or -1 (result set). */
static int32_t put_routes(void)
{
    int32_t count = 0;

    for (int hostname = 0; hostname < 2; hostname++) {
        int32_t rc = get_routes(hostname);
        const char *end = s_resp + s_resp_len;

        if (rc != 200) {
            fail(hostname ? "GET hostname routes" : "GET teamnet routes", rc);
            return -1;
        }
        for (const char *r = cj_first(cj_member(s_resp, end, "result"), end); r; r = cj_next(r, end)) {
            if (!cj_skip(r, end)) {
                s_trunc = 1;
                break;
            }
            row_begin();
            P(count ? ",[" : "[");
            P(hostname ? "\"hostname\"," : "\"network\",");
            put_jstr(cj_member(r, end, hostname ? "hostname" : "network"), end, 120);
            P(",");
            put_jstr(cj_member(r, end, "comment"), end, 100);
            P(",");
            put_jstr(cj_member(r, end, "id"), end, 40);
            P("]");
            if (!row_end()) {
                break;
            }
            count++;
        }
    }
    return count;
}

/* POSTs a route for s_tun_id: {"network"|"hostname": target, "tunnel_id", "comment"?}. */
static int32_t post_route(int hostname, const char *target, const char *comment)
{
    claw_buf_t body = { s_body, sizeof(s_body), 0, 0 };

    bput(&body, hostname ? "{\"hostname\":\"" : "{\"network\":\"");
    bput(&body, target);
    bput(&body, "\",\"tunnel_id\":\"");
    bput(&body, s_tun_id);
    if (comment[0]) {
        bput(&body, "\",\"comment\":\"");
        bput(&body, comment); /* still JSON-escaped from the arguments */
    }
    bput(&body, "\"}");
    path_begin("/accounts/");
    bput(&s_p, s_acct);
    bput(&s_p, hostname ? "/zerotrust/routes/hostname" : "/teamnet/routes");
    return http("POST", body.buf, body.len);
}

#define RUN_HINT "On the other host: cloudflared tunnel run --token <token>. Get the token from the dashboard " \
                 "(Networks > Tunnels) or with `cloudflared tunnel token <id>`; it never passes through this device."

static void tool_tunnel_create(void)
{
    char name[64];
    char net[64];
    char rid[40] = "";
    int32_t nn = arg_str("name", name, sizeof(name));
    int32_t netn = arg_str("network", net, sizeof(net));
    claw_buf_t body = { s_body, sizeof(s_body), 0, 0 };
    const char *end;
    int32_t rc;

    if (!is_tunnel_name(name, nn)) {
        err_result("name is required: up to 63 letters, digits, '.', '-', '_'", 0);
        return;
    }
    if (cj_member(s_args, s_args_end, "network") && !is_cidr(net, netn)) {
        err_result("network must be a CIDR like 192.168.1.0/24", 0);
        return;
    }
    if (!account()) {
        return;
    }
    /* Remotely managed: ingress and routes live in Cloudflare, cloudflared only needs the token. */
    bput(&body, "{\"name\":\"");
    bput(&body, name);
    bput(&body, "\",\"config_src\":\"cloudflare\"}");
    path_begin("/accounts/");
    bput(&s_p, s_acct);
    bput(&s_p, "/cfd_tunnel");
    rc = http("POST", body.buf, body.len);
    end = s_resp + s_resp_len;
    /* The response also carries the connector token; only id and name are read from it. */
    if (rc != 200) {
        account_check(rc);
        fail("POST cfd_tunnel", rc);
        return;
    }
    if (cj_string(mem(s_resp, end, "result", "id"), end, s_tun_id, sizeof(s_tun_id)) != 36) {
        err_result("tunnel created but its id is missing; check cf_tunnels", 0); /* no raw dump: token inside */
        return;
    }
    for (int32_t i = 0; i <= nn; i++) {
        s_tun_name[i] = name[i];
    }
    if (netn > 0) {
        rc = post_route(0, net, "");
        end = s_resp + s_resp_len;
        if (rc != 200 || cj_string(mem(s_resp, end, "result", "id"), end, rid, sizeof(rid)) <= 0) {
            const char *msg = cj_member(cj_first(cj_member(s_resp, end, "errors"), end), end, "message");

            out_begin();
            P("{\"ok\":false,\"tunnel\":");
            put_tun_name();
            P(",\"id\":\"");
            P(s_tun_id);
            P("\",\"error\":\"tunnel created, route failed; retry with cf_tunnel_route\",\"status\":");
            put_i32(rc);
            P(",\"detail\":");
            put_jstr(msg, end, 200);
            P("}");
            out_end();
            return;
        }
    }
    out_begin();
    P("{\"ok\":true,\"tunnel\":");
    put_tun_name();
    P(",\"id\":\"");
    P(s_tun_id);
    P("\"");
    if (rid[0]) {
        P(",\"network\":\"");
        P(net);
        P("\",\"route_id\":\"");
        P(rid);
        P("\"");
    }
    P(",\"next\":\"" RUN_HINT "\"}");
    out_end();
}

static void tool_tunnel_route(void)
{
    char target[256];
    char comment[101] = "";
    int has_net = cj_member(s_args, s_args_end, "network") != 0;
    int hostname = cj_member(s_args, s_args_end, "hostname") != 0;
    int remove = arg_bool("remove") == 1;
    int32_t tn = arg_str(hostname ? "hostname" : "network", target, sizeof(target));
    const char *end;
    char rid[40] = "";
    int32_t rc;

    if (has_net && hostname) {
        err_result("pass network or hostname, not both", 0);
        return;
    }
    if (has_net && !is_cidr(target, tn)) {
        err_result("network must be a CIDR like 192.168.1.0/24", 0);
        return;
    }
    if (hostname && !is_name(target, tn, 0)) {
        err_result("hostname must be a host name like app.example.com", 0);
        return;
    }
    if (cj_member(s_args, s_args_end, "comment") && arg_str("comment", comment, sizeof(comment)) < 0) {
        err_result("comment must be a string of up to 100 bytes", 0);
        return;
    }
    if (remove && !has_net && !hostname) {
        err_result("remove needs the network or hostname of the route", 0);
        return;
    }
    if (!tunnel()) {
        return;
    }

    if (!has_net && !hostname) {
        int32_t n;

        out_begin();
        P("{\"tunnel\":");
        put_tun_name();
        P(",\"cols\":" ROUTE_COLS ",\"rows\":[");
        if ((n = put_routes()) < 0) {
            return;
        }
        s_b.cap = sizeof(s_out);
        P("],\"count\":");
        put_i32(n);
        P(s_trunc ? ",\"truncated\":true}" : "}");
        out_end();
        return;
    }

    if (remove) {
        rc = get_routes(hostname);
        end = s_resp + s_resp_len;
        if (rc != 200) {
            fail(hostname ? "GET hostname routes" : "GET teamnet routes", rc);
            return;
        }
        for (const char *r = cj_first(cj_member(s_resp, end, "result"), end); r; r = cj_next(r, end)) {
            char v[256];
            int32_t vl = cj_string(cj_member(r, end, hostname ? "hostname" : "network"), end, v, sizeof(v));

            if (vl == tn && str_eq(v, (uint32_t)vl, target)) {
                cj_string(cj_member(r, end, "id"), end, rid, sizeof(rid));
                break;
            }
        }
        if (!is_uuid(rid, claw_strlen(rid))) {
            err_result("the tunnel has no such route", target);
            return;
        }
        path_begin("/accounts/");
        bput(&s_p, s_acct);
        bput(&s_p, hostname ? "/zerotrust/routes/hostname/" : "/teamnet/routes/");
        bput(&s_p, rid);
        rc = http("DELETE", "", 0);
        if (rc != 200) {
            fail(hostname ? "DELETE hostname route" : "DELETE teamnet route", rc);
            return;
        }
    } else {
        rc = post_route(hostname, target, comment);
        end = s_resp + s_resp_len;
        if (rc != 200) {
            fail(hostname ? "POST hostname route" : "POST teamnet route", rc);
            return;
        }
        cj_string(mem(s_resp, end, "result", "id"), end, rid, sizeof(rid));
    }
    out_begin();
    P(remove ? "{\"ok\":true,\"action\":\"removed\",\"tunnel\":" : "{\"ok\":true,\"action\":\"added\",\"tunnel\":");
    put_tun_name();
    P(hostname ? ",\"hostname\":\"" : ",\"network\":\"");
    P(target);
    P("\",\"route_id\":\"");
    P(rid);
    P(s_tun_up || remove ? "\"}" : "\",\"note\":\"tunnel has no connector yet: start cloudflared on the host\"}");
    out_end();
}

static void tool_tunnel_delete(void)
{
    int32_t n;
    int32_t rc;

    if (!tunnel()) {
        return;
    }
    if (s_tun_up) {
        err_result("tunnel still has connections; stop cloudflared on the host first", 0);
        return;
    }
    /* Routes are not removed implicitly: each removal is its own confirmed request. */
    out_begin();
    P("{\"error\":\"remove the tunnel's routes first (cf_tunnel_route remove=true)\",\"cols\":" ROUTE_COLS
      ",\"rows\":[");
    if ((n = put_routes()) < 0) {
        return;
    }
    if (n > 0) {
        s_b.cap = sizeof(s_out);
        P("]}");
        out_end();
        return;
    }
    path_begin("/accounts/");
    bput(&s_p, s_acct);
    bput(&s_p, "/cfd_tunnel/");
    bput(&s_p, s_tun_id);
    rc = http("DELETE", "", 0);
    if (rc != 200) {
        fail("DELETE cfd_tunnel", rc);
        return;
    }
    out_begin();
    P("{\"ok\":true,\"action\":\"deleted\",\"tunnel\":");
    put_tun_name();
    P(",\"id\":\"");
    P(s_tun_id);
    P("\"}");
    out_end();
}

static void tool_workers(void)
{
    const char *end;
    uint32_t count = 0;
    int32_t rc;

    if (!account()) {
        return;
    }
    path_begin("/accounts/");
    bput(&s_p, s_acct);
    bput(&s_p, "/workers/scripts");
    rc = get();
    end = s_resp + s_resp_len;
    if (rc != 200) {
        account_check(rc);
        fail("GET workers/scripts", rc);
        return;
    }
    out_begin();
    P("{\"cols\":[\"name\",\"modified\",\"handlers\"],\"rows\":[");
    for (const char *w = cj_first(cj_member(s_resp, end, "result"), end); w; w = cj_next(w, end)) {
        uint32_t nh = 0;

        if (!cj_skip(w, end)) {
            s_trunc = 1;
            break;
        }
        row_begin();
        P(count ? ",[" : "[");
        put_jstr(cj_member(w, end, "id"), end, 80);
        P(",");
        put_jcut(cj_member(w, end, "modified_on"), end, 10);
        P(",\"");
        for (const char *h = cj_first(cj_member(w, end, "handlers"), end); h && nh < 6; h = cj_next(h, end)) {
            const char *close = *h == '"' ? cj_skip(h, end) : 0;

            if (close) {
                P(nh++ ? " " : "");
                put_safe(h + 1, close - 1, 24, SAFE_JSON);
            }
        }
        P("\"]");
        if (!row_end()) {
            break;
        }
        count++;
    }
    s_b.cap = sizeof(s_out);
    P("],\"count\":");
    bput_u32(&s_b, count);
    P(s_trunc ? ",\"truncated\":true}" : "}");
    out_end();
}

/* "YYYY-MM-DDTHH:00:00Z" for a Unix time in seconds (hour precision). */
static void put_iso_hour(claw_buf_t *b, int64_t secs)
{
    int64_t days = secs / 86400;
    int64_t hour = (secs % 86400) / 3600;
    /* civil_from_days (H. Hinnant) */
    int64_t z = days + 719468;
    int64_t era = z / 146097;
    int64_t doe = z - era * 146097;
    int64_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    int64_t y = yoe + era * 400;
    int64_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    int64_t mp = (5 * doy + 2) / 153;
    int64_t d = doy - (153 * mp + 2) / 5 + 1;
    int64_t m = mp < 10 ? mp + 3 : mp - 9;
    char s[21];

    y += m <= 2;
    s[0] = (char)('0' + y / 1000 % 10);
    s[1] = (char)('0' + y / 100 % 10);
    s[2] = (char)('0' + y / 10 % 10);
    s[3] = (char)('0' + y % 10);
    s[4] = '-';
    s[5] = (char)('0' + m / 10);
    s[6] = (char)('0' + m % 10);
    s[7] = '-';
    s[8] = (char)('0' + d / 10);
    s[9] = (char)('0' + d % 10);
    s[10] = 'T';
    s[11] = (char)('0' + hour / 10);
    s[12] = (char)('0' + hour % 10);
    s[13] = ':';
    s[14] = '0';
    s[15] = '0';
    s[16] = ':';
    s[17] = '0';
    s[18] = '0';
    s[19] = 'Z';
    s[20] = '\0';
    bput(b, s);
}

static void tool_analytics(void)
{
    int64_t hours = arg_int("since_hours", 24);
    int64_t now = claw_now_ms() / 1000;
    claw_buf_t body = { s_body, sizeof(s_body), 0, 0 };
    uint64_t req = 0, cached = 0, bytes = 0, threats = 0, views = 0;
    uint32_t n = 0;
    const char *end;
    const char *groups;
    int32_t rc;

    if (hours < 1 || hours > 72) {
        err_result("since_hours must be 1-72", 0);
        return;
    }
    if (now < 1577836800) {
        err_result("device clock not synced yet", 0);
        return;
    }
    if (!zone()) {
        return;
    }
    /* GraphQL Analytics API; httpRequests1hGroups is available on all plans (retention depends on the
     * plan). UNVERIFIED on the live API: the `Time` type of $s and the 100-group limit. */
    bput(&body, "{\"query\":\"query($z:String!,$s:Time!){viewer{zones(filter:{zoneTag:$z}){"
           "httpRequests1hGroups(limit:100,orderBy:[datetime_ASC],filter:{datetime_geq:$s}){"
           "dimensions{datetime}sum{requests cachedRequests bytes threats pageViews}}}}}\","
           "\"variables\":{\"z\":\"");
    bput(&body, s_zone_id);
    bput(&body, "\",\"s\":\"");
    put_iso_hour(&body, now - hours * 3600);
    bput(&body, "\"}}");
    path_begin("/graphql");
    rc = http("POST", body.buf, body.len);
    end = s_resp + s_resp_len;
    groups = mem(cj_first(mem(cj_member(s_resp, end, "data"), end, "viewer", "zones"), end), end,
                 "httpRequests1hGroups", 0);
    if (rc != 200 || !groups) {
        fail("POST /graphql", rc);
        return;
    }
    out_begin();
    P("{\"zone\":\"");
    P(s_zone);
    P("\",\"since\":\"");
    put_iso_hour(&s_b, now - hours * 3600);
    P("\",\"hourly_requests\":[");
    for (const char *g = cj_first(groups, end); g; g = cj_next(g, end)) {
        const char *sum = cj_member(g, end, "sum");
        int64_t r = cj_uint(cj_member(sum, end, "requests"), end);
        int64_t v;

        if (!cj_skip(g, end)) {
            s_trunc = 1;
            break;
        }
        req += r > 0 ? (uint64_t)r : 0;
        cached += (v = cj_uint(cj_member(sum, end, "cachedRequests"), end)) > 0 ? (uint64_t)v : 0;
        bytes += (v = cj_uint(cj_member(sum, end, "bytes"), end)) > 0 ? (uint64_t)v : 0;
        threats += (v = cj_uint(cj_member(sum, end, "threats"), end)) > 0 ? (uint64_t)v : 0;
        views += (v = cj_uint(cj_member(sum, end, "pageViews"), end)) > 0 ? (uint64_t)v : 0;
        P(n++ ? "," : "");
        put_u64(r > 0 ? (uint64_t)r : 0);
    }
    s_b.cap = sizeof(s_out);
    P("],\"hours_with_data\":");
    bput_u32(&s_b, n);
    P(",\"requests\":");
    put_u64(req);
    P(",\"cached\":");
    put_u64(cached);
    P(",\"bytes\":");
    put_u64(bytes);
    P(",\"threats\":");
    put_u64(threats);
    P(",\"page_views\":");
    put_u64(views);
    P(s_trunc ? ",\"truncated\":true}" : "}");
    out_end();
}

/* ---------- registration and dispatch ---------- */

#define TUNNEL_PROP "\"tunnel\":{\"type\":\"string\",\"description\":\"Tunnel name or id\"}"
#define ZONE_PROP "\"zone\":{\"type\":\"string\",\"description\":\"Zone name (example.com) or zone id\"}"

CLAW_EXPORT("app_init") void app_init(void)
{
    s_t_zones = CLAW_REGISTER("zones", "List the account's Cloudflare zones: name, status, plan, id. verify=true also "
                              "checks the account-owned API token.",
                              "{\"type\":\"object\",\"properties\":{\"verify\":{\"type\":\"boolean\"}}}");
    s_t_list = CLAW_REGISTER("dns_list", "List DNS records of a zone as rows [name (relative, @ = apex), type, "
                             "content, ttl (1 = auto), proxied, id]. Optional type and name filters.",
                             "{\"type\":\"object\",\"properties\":{" ZONE_PROP ",\"type\":{\"type\":\"string\"},"
                             "\"name\":{\"type\":\"string\",\"description\":\"www, @ or full name\"}},"
                             "\"required\":[\"zone\"]}");
    s_t_upsert = CLAW_REGISTER("dns_upsert", "Create or update a DNS record (matched by name+type, or record_id when "
                               "several match). The user confirms the change in Telegram. Unchanged records are "
                               "not written.",
                               "{\"type\":\"object\",\"properties\":{" ZONE_PROP ",\"type\":{\"type\":\"string\"},"
                               "\"name\":{\"type\":\"string\",\"description\":\"www, @ or full name\"},"
                               "\"content\":{\"type\":\"string\"},\"ttl\":{\"type\":\"integer\",\"description\":"
                               "\"1 = auto\"},\"proxied\":{\"type\":\"boolean\"},\"record_id\":{\"type\":\"string\"}},"
                               "\"required\":[\"zone\",\"type\",\"name\",\"content\"]}");
    s_t_delete = CLAW_REGISTER("dns_delete", "Delete a DNS record by record_id, or by name+type when exactly one "
                               "matches. The user confirms in Telegram.",
                               "{\"type\":\"object\",\"properties\":{" ZONE_PROP ",\"record_id\":{\"type\":\"string\"},"
                               "\"name\":{\"type\":\"string\"},\"type\":{\"type\":\"string\"}},\"required\":[\"zone\"]}");
    s_t_purge = CLAW_REGISTER("purge", "Purge Cloudflare cache of a zone: urls (full URLs, max 30) or everything=true. "
                              "The user confirms in Telegram.",
                              "{\"type\":\"object\",\"properties\":{" ZONE_PROP ",\"urls\":{\"type\":\"array\","
                              "\"items\":{\"type\":\"string\"}},\"everything\":{\"type\":\"boolean\"}},"
                              "\"required\":[\"zone\"]}");
    s_t_tunnels = CLAW_REGISTER("tunnels", "List Cloudflare Tunnels: name, status (healthy/degraded/down/inactive), "
                                "connection count, data centers, since, id.",
                                "{\"type\":\"object\",\"properties\":{}}");
    s_t_tun_create = CLAW_REGISTER("tunnel_create", "Create a remotely managed Cloudflare Tunnel, optionally with a "
                                   "private network route (CIDR) so WARP clients reach or egress through the host "
                                   "that runs cloudflared. Returns the id and how to start cloudflared; the connector "
                                   "token is never returned. The user confirms each request in Telegram.",
                                   "{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\"},"
                                   "\"network\":{\"type\":\"string\",\"description\":\"CIDR, e.g. 192.168.1.0/24\"}},"
                                   "\"required\":[\"name\"]}");
    s_t_tun_route = CLAW_REGISTER("tunnel_route", "Routes of a tunnel. Without network/hostname: list them. With "
                                  "network (CIDR) or hostname (public hostname that egresses through the tunnel): "
                                  "add the route, or remove it with remove=true. The user confirms in Telegram.",
                                  "{\"type\":\"object\",\"properties\":{" TUNNEL_PROP ",\"network\":{\"type\":"
                                  "\"string\"},\"hostname\":{\"type\":\"string\"},\"comment\":{\"type\":\"string\"},"
                                  "\"remove\":{\"type\":\"boolean\"}},\"required\":[\"tunnel\"]}");
    s_t_tun_delete = CLAW_REGISTER("tunnel_delete", "Delete a tunnel. cloudflared must be stopped and its routes "
                                   "removed first. The user confirms in Telegram.",
                                   "{\"type\":\"object\",\"properties\":{" TUNNEL_PROP "},\"required\":[\"tunnel\"]}");
    s_t_workers = CLAW_REGISTER("workers", "List Workers scripts: name, last modified date, handlers.",
                                "{\"type\":\"object\",\"properties\":{}}");
    s_t_analytics = CLAW_REGISTER("analytics", "HTTP traffic of a zone for the last since_hours (1-72, default 24): "
                                  "requests, cached, bytes, threats, page views, hourly requests. Uses a GraphQL POST, "
                                  "so the user confirms in Telegram.",
                                  "{\"type\":\"object\",\"properties\":{" ZONE_PROP ",\"since_hours\":{\"type\":"
                                  "\"integer\"}},\"required\":[\"zone\"]}");
}

CLAW_EXPORT("tool_call") int32_t tool_call(int32_t tool, const char *args, uint32_t len)
{
    s_args = args;
    s_args_end = args + len;
    if (tool == s_t_zones) {
        tool_zones();
    } else if (tool == s_t_list) {
        tool_dns_list();
    } else if (tool == s_t_upsert) {
        tool_dns_upsert();
    } else if (tool == s_t_delete) {
        tool_dns_delete();
    } else if (tool == s_t_purge) {
        tool_purge();
    } else if (tool == s_t_tunnels) {
        tool_tunnels();
    } else if (tool == s_t_tun_create) {
        tool_tunnel_create();
    } else if (tool == s_t_tun_route) {
        tool_tunnel_route();
    } else if (tool == s_t_tun_delete) {
        tool_tunnel_delete();
    } else if (tool == s_t_workers) {
        tool_workers();
    } else if (tool == s_t_analytics) {
        tool_analytics();
    } else {
        return -1;
    }
    return 0;
}
