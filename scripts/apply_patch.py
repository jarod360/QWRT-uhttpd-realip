#!/usr/bin/env python3
"""Apply trusted X-Real-IP changes to pinned upstream uhttpd source."""
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
# Append the new member to preserve offsets of existing struct client members
# consumed by separately-built uhttpd plugins.
replace_once("uhttpd.h", "\tstruct dispatch dispatch;\n};",
    "\tstruct dispatch dispatch;\n\tstruct uh_addr remote_addr;\n};")

replace_once("main.c", "#include <sys/socket.h>\n#include <netinet/in.h>",
    "#include <sys/socket.h>\n#include <arpa/inet.h>\n#include <netinet/in.h>")
replace_once("main.c", "Enable RFC1918 filter\\\\n",
    "Enable RFC1918 filter\\\\n\\\\t-z address      Trust this reverse proxy for X-Real-IP (repeatable)\\\\n")
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
    " */\n\n#include <arpa/inet.h>\n#include <libubox/blobmsg.h>")
replace_once("client.c", "static bool rfc1918_filter_check(struct client *cl)\n{",
r"""/*
 * X-Real-IP is accepted only when the TCP peer is explicitly trusted.
 * remote_addr is immutable for the lifetime of the connection; peer_addr
 * is reset from it for every request to prevent keep-alive state leakage.
 */
static void client_update_real_ip(struct client *cl)
{
    struct real_ip_trusted *trusted;
    struct blob_attr *cur;
    struct uh_addr candidate = { 0 };
    const char *value = NULL;
    int matches = 0, rem;
    bool allowed = false;

    cl->peer_addr = cl->remote_addr;

    list_for_each_entry(trusted, &conf.real_ip_trusted, list) {
        if (trusted->addr.family != cl->remote_addr.family)
            continue;

        if (trusted->addr.family == AF_INET &&
            trusted->addr.in.s_addr == cl->remote_addr.in.s_addr)
            allowed = true;
        else if (trusted->addr.family == AF_INET6 &&
                 !memcmp(&trusted->addr.in6, &cl->remote_addr.in6,
                         sizeof(struct in6_addr)))
            allowed = true;

        if (allowed)
            break;
    }

    if (!allowed)
        return;

    blob_for_each_attr(cur, cl->hdr.head, rem) {
        if (strcmp(blobmsg_name(cur), "x-real-ip"))
            continue;
        matches++;
        value = blobmsg_get_string(cur);
    }

    /* Reject duplicate values and comma-separated proxy chains. */
    if (matches != 1 || !value || strchr(value, ','))
        return;

    if (inet_pton(AF_INET, value, &candidate.in) == 1)
        candidate.family = AF_INET;
    else if (inet_pton(AF_INET6, value, &candidate.in6) == 1)
        candidate.family = AF_INET6;
    else
        return;

    cl->peer_addr.family = candidate.family;
    if (candidate.family == AF_INET)
        cl->peer_addr.in = candidate.in;
    else
        cl->peer_addr.in6 = candidate.in6;
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

print("Applied trusted X-Real-IP support to uhttpd source and init script.")
