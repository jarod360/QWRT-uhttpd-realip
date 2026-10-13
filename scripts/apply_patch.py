#!/usr/bin/env python3
"""Apply trusted X-Real-IP and X-Forwarded-For support to pinned uhttpd."""
from pathlib import Path
import sys

ROOT = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path.cwd()
PACKAGE = Path(sys.argv[2]).resolve() if len(sys.argv) > 2 else ROOT


def replace_once(path, old, new):
    file_path = Path(path)
    if not file_path.is_absolute():
        file_path = ROOT / file_path
    content = file_path.read_text()
    count = content.count(old)
    if count != 1:
        raise SystemExit(f"{file_path}: expected one patch anchor, found {count}: {old[:100]!r}")
    file_path.write_text(content.replace(old, new, 1))


replace_once("uhttpd.h",
    "\tstruct list_head sni_redirect;\n};\n\nstruct sni_redirect {",
    "\tstruct list_head sni_redirect;\n\tstruct list_head real_ip_trusted;\n};\n\nstruct sni_redirect {")
replace_once("uhttpd.h",
    "struct sni_redirect {\n\tstruct list_head list;\n\tconst char *host;\n\tconst char *url;\n};",
    "struct sni_redirect {\n\tstruct list_head list;\n\tconst char *host;\n\tconst char *url;\n};\n\nstruct real_ip_trusted {\n\tstruct list_head list;\n\tstruct uh_addr addr;\n};")
# Append this field to preserve offsets of existing struct client members
# consumed by separately-built uhttpd plugins.
replace_once("uhttpd.h", "\tstruct dispatch dispatch;\n};",
    "\tstruct dispatch dispatch;\n\tstruct uh_addr remote_addr;\n};")

replace_once("main.c", "#include <sys/socket.h>\n#include <netinet/in.h>",
    "#include <sys/socket.h>\n#include <arpa/inet.h>\n#include <netinet/in.h>")
replace_once("main.c", r"Enable RFC1918 filter\n",
    r"Enable RFC1918 filter\n\t-z address      Trust this reverse proxy for forwarded client IP headers (repeatable)\n")
replace_once("main.c", "\tINIT_LIST_HEAD(&conf.sni_redirect);\n}",
    "\tINIT_LIST_HEAD(&conf.sni_redirect);\n\tINIT_LIST_HEAD(&conf.real_ip_trusted);\n}")
replace_once("main.c", "static void init_defaults_post(void)\n{",
r"""static void add_real_ip_trusted(const char *value)
{
    struct real_ip_trusted *entry;

    entry = calloc(1, sizeof(*entry));
    if (!entry) {
        perror("calloc");
        exit(1);
    }

    if (inet_pton(AF_INET, value, &entry->addr.in) == 1)
        entry->addr.family = AF_INET;
    else if (inet_pton(AF_INET6, value, &entry->addr.in6) == 1)
        entry->addr.family = AF_INET6;
    else {
        fprintf(stderr, "uhttpd: invalid trusted proxy address: %s\n", value);
        free(entry);
        exit(1);
    }

    list_add_tail(&entry->list, &conf.real_ip_trusted);
}

static void init_defaults_post(void)
{""")
replace_once("main.c",
    '"A:ab:C:c:Dd:E:e:fh:H:I:i:K:k:L:l:m:N:n:O:o:P:p:qQ:Rr:Ss:T:t:U:u:Xx:y:"',
    '"A:ab:C:c:Dd:E:e:fh:H:I:i:K:k:L:l:m:N:n:O:o:P:p:qQ:Rr:Ss:T:t:U:u:Xx:y:z:"')
replace_once("main.c", "\t\tcase 'R':\n\t\t\tconf.rfc1918_filter = 1;\n\t\t\tbreak;\n",
    "\t\tcase 'R':\n\t\t\tconf.rfc1918_filter = 1;\n\t\t\tbreak;\n\n\t\tcase 'z':\n\t\t\tadd_real_ip_trusted(optarg);\n\t\t\tbreak;\n")

replace_once("client.c", " */\n\n#include <libubox/blobmsg.h>",
    " */\n\n#include <arpa/inet.h>\n#include <ctype.h>\n#include <libubox/blobmsg.h>")
replace_once("client.c", "static bool rfc1918_filter_check(struct client *cl)\n{",
r"""/*
 * Only explicitly trusted TCP peers may supply forwarding headers.
 * Walk X-Forwarded-For from right to left, skipping trusted proxy hops.
 * The raw TCP peer is immutable and peer_addr is reset on every request.
 */
static bool real_ip_addr_equal(const struct uh_addr *a, const struct uh_addr *b)
{
    if (a->family != b->family)
        return false;

    if (a->family == AF_INET)
        return a->in.s_addr == b->in.s_addr;

    if (a->family == AF_INET6)
        return !memcmp(&a->in6, &b->in6, sizeof(struct in6_addr));

    return false;
}

static bool real_ip_is_trusted(const struct uh_addr *addr)
{
    struct real_ip_trusted *entry;

    list_for_each_entry(entry, &conf.real_ip_trusted, list) {
        if (real_ip_addr_equal(addr, &entry->addr))
            return true;
    }

    return false;
}

static bool real_ip_parse(const char *value, struct uh_addr *addr)
{
    char buf[INET6_ADDRSTRLEN];
    const char *start = value;
    size_t len;

    while (*start && isspace((unsigned char)*start))
        start++;

    len = strlen(start);
    while (len && isspace((unsigned char)start[len - 1]))
        len--;

    if (!len || len >= sizeof(buf))
        return false;

    memcpy(buf, start, len);
    buf[len] = '\0';

    memset(addr, 0, sizeof(*addr));
    if (inet_pton(AF_INET, buf, &addr->in) == 1) {
        addr->family = AF_INET;
        return true;
    }

    if (inet_pton(AF_INET6, buf, &addr->in6) == 1) {
        addr->family = AF_INET6;
        return true;
    }

    return false;
}

static bool real_ip_get_header(struct client *cl, const char *name,
                               const char **value)
{
    struct blob_attr *cur;
    int rem, matches = 0;

    *value = NULL;
    blob_for_each_attr(cur, cl->hdr.head, rem) {
        if (strcmp(blobmsg_name(cur), name))
            continue;

        matches++;
        *value = blobmsg_get_string(cur);
    }

    return matches == 1 && *value;
}

static void client_update_real_ip(struct client *cl)
{
    struct uh_addr candidate;
    const char *value = NULL;
    char *copy = NULL, *p, *comma;
    char **parts = NULL;
    size_t count = 1, i;
    bool found = false, malformed = false;

    cl->peer_addr = cl->remote_addr;

    if (!real_ip_is_trusted(&cl->remote_addr))
        return;

    /*
     * Prefer X-Forwarded-For: it preserves the proxy chain and can identify
     * the client across multiple trusted reverse proxies. Parse from right
     * to left and stop at the first non-trusted address.
     */
    if (real_ip_get_header(cl, "x-forwarded-for", &value) && *value) {
        for (p = (char *)value; *p; p++) {
            if (*p == ',')
                count++;
        }

        if (count <= UH_LIMIT_HEADER_COUNT) {
            copy = strdup(value);
            parts = calloc(count, sizeof(*parts));
            if (copy && parts) {
                p = copy;
                for (i = 0; i < count; i++) {
                    parts[i] = p;
                    comma = strchr(p, ',');
                    if (comma) {
                        *comma = '\0';
                        p = comma + 1;
                    } else if (i != count - 1) {
                        malformed = true;
                        break;
                    }
                }

                if (!malformed) {
                    for (i = count; i > 0; i--) {
                        if (!real_ip_parse(parts[i - 1], &candidate)) {
                            malformed = true;
                            break;
                        }

                        if (real_ip_is_trusted(&candidate))
                            continue;

                        found = true;
                        break;
                    }
                }
            }
        }
    }

    if (found && !malformed)
        cl->peer_addr = candidate;

    free(parts);
    free(copy);

    if (found && !malformed)
        return;

    /*
     * X-Real-IP is the fallback for proxies that provide a single client IP
     * but do not provide a usable X-Forwarded-For chain.
     */
    if (real_ip_get_header(cl, "x-real-ip", &value) &&
        !strchr(value, ',') && real_ip_parse(value, &candidate))
        cl->peer_addr = candidate;
}

static bool rfc1918_filter_check(struct client *cl)
{""")
replace_once("client.c",
    "\tif (!request_header_check(cl))\n\t\treturn;\n\n\tif (!rfc1918_filter_check(cl))",
    "\tif (!request_header_check(cl))\n\t\treturn;\n\n\tclient_update_real_ip(cl);\n\n\tif (!rfc1918_filter_check(cl))")
replace_once("client.c", "\tset_addr(&cl->peer_addr, &addr);\n\tsl = sizeof(addr);",
    "\tset_addr(&cl->peer_addr, &addr);\n\tcl->remote_addr = cl->peer_addr;\n\tsl = sizeof(addr);")

replace_once(str(PACKAGE / "files/uhttpd.init"), "append_bool() {\n",
    'append_real_ip_trusted() {\n\tlocal addr="$1"\n\t[ -n "$addr" ] && procd_append_param command -z "$addr"\n}\n\nappend_bool() {\n')
replace_once(str(PACKAGE / "files/uhttpd.init"),
    '\tappend_bool "$cfg" rfc1918_filter "-R" 0\n',
    '\tappend_bool "$cfg" rfc1918_filter "-R" 0\n'
    '\tconfig_list_foreach "$cfg" set_real_ip_from append_real_ip_trusted\n')

print("Applied trusted X-Real-IP and X-Forwarded-For support to uhttpd.")
