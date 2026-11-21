#!/usr/bin/env python3
"""Apply a fail-closed, trusted X-Real-IP extension to the pinned uhttpd source.

Usage: apply_patch.py <prepared-uhttpd-source-dir> <openwrt-uhttpd-package-dir>
The pinned upstream revision is 60f64bec40c8113cf09815ec377761b1f4f95f22.
A missing upstream anchor aborts rather than silently producing an unpatched IPK.
"""
from pathlib import Path
import sys


def replace_once(text, old, new, label):
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one anchor, found {count}: {old[:100]!r}")
    return text.replace(old, new, 1)


def patch(source_dir, package_dir):
    paths = {
        "main": source_dir / "main.c",
        "client": source_dir / "client.c",
        "header": source_dir / "uhttpd.h",
        "init": package_dir / "files" / "uhttpd.init",
        "config": package_dir / "files" / "uhttpd.config",
    }
    result = {key: path.read_text() for key, path in paths.items()}

    main = result["main"]
    main = replace_once(
        main, "#include <netinet/in.h>\n",
        "#include <netinet/in.h>\n#include <arpa/inet.h>\n", "main.c include"
    )
    main = replace_once(
        main, "static int usage(const char *name)\n{",
        """static void add_realip_trusted(const char *address)
{
\tstruct realip_trust *proxy = calloc(1, sizeof(*proxy));

\tif (!proxy)
\t\treturn;

\tif (inet_pton(AF_INET, address, &proxy->addr.in) == 1)
\t\tproxy->addr.family = AF_INET;
\telse if (inet_pton(AF_INET6, address, &proxy->addr.in6) == 1)
\t\tproxy->addr.family = AF_INET6;
\telse {
\t\tfprintf(stderr, "uhttpd: ignoring invalid trusted proxy IP: %s\\n", address);
\t\tfree(proxy);
\t\treturn;
\t}

\tlist_add_tail(&proxy->list, &conf.realip_trusted);
}

static int usage(const char *name)
{""",
        "main.c trusted proxy parser"
    )
    main = replace_once(
        main,
        'Enable RFC1918 filter\\n"\n',
        'Enable RFC1918 filter\\n"\n\t\t"\\t-J ip           Trust X-Real-IP only from this proxy IP (repeatable)\\n"\n',
        "main.c help"
    )
    main = replace_once(
        main, "INIT_LIST_HEAD(&conf.cgi_alias);",
        "INIT_LIST_HEAD(&conf.cgi_alias);\n\tINIT_LIST_HEAD(&conf.realip_trusted);",
        "main.c list initialization"
    )
    main = replace_once(
        main,
        '"A:ab:C:c:Dd:E:e:fh:H:I:i:K:k:L:l:m:N:n:O:o:P:p:qQ:Rr:Ss:T:t:U:u:Xx:y:"',
        '"A:ab:C:c:Dd:E:e:fh:H:I:i:K:k:L:l:m:N:n:O:o:P:p:qQ:Rr:Ss:T:t:U:u:Xx:y:J:"',
        "main.c getopt"
    )
    main = replace_once(
        main,
        "\t\tcase 'R':\n\t\t\tconf.rfc1918_filter = 1;\n\t\t\tbreak;",
        "\t\tcase 'R':\n\t\t\tconf.rfc1918_filter = 1;\n\t\t\tbreak;\n\n"
        "\t\tcase 'J':\n\t\t\tadd_realip_trusted(optarg);\n\t\t\tbreak;",
        "main.c option handling"
    )
    result["main"] = main

    header = result["header"]
    header = replace_once(
        header, "struct client;\n",
        """struct client;

struct realip_trust {
\tstruct list_head list;
\tstruct uh_addr addr;
};
""",
        "uhttpd.h trust declaration"
    )
    header = replace_once(
        header, "\tstruct list_head cgi_alias;",
        "\tstruct list_head cgi_alias;\n\tstruct list_head realip_trusted;",
        "uhttpd.h trust list"
    )
    header = replace_once(
        header, "\tstruct uh_addr srv_addr, peer_addr;",
        "\tstruct uh_addr srv_addr, peer_addr, socket_peer_addr;",
        "uhttpd.h socket peer storage"
    )
    result["header"] = header

    client = result["client"]
    client = replace_once(
        client, "#include <libubox/blobmsg.h>\n",
        "#include <arpa/inet.h>\n#include <libubox/blobmsg.h>\n",
        "client.c inet_pton include"
    )
    client = replace_once(
        client,
        "\t*newline = 0;\n\tblob_buf_init(&cl->hdr, 0);",
        "\t*newline = 0;\n"
        "\t/* A keep-alive connection may carry a different client IP each request. */\n"
        "\tcl->peer_addr = cl->socket_peer_addr;\n"
        "\tblob_buf_init(&cl->hdr, 0);",
        "client.c keep-alive reset"
    )
    client = replace_once(
        client,
        "static void client_header_complete(struct client *cl)\n{",
        """static void client_apply_realip(struct client *cl)
{
\tstruct realip_trust *proxy;
\tstruct blob_attr *cur;
\tstruct uh_addr addr = {0};
\tconst char *forwarded = NULL;
\tbool trusted = false;
\tint rem;

\t/* Trust the original TCP peer, never the request header itself. */
\tlist_for_each_entry(proxy, &conf.realip_trusted, list) {
\t\tif (proxy->addr.family != cl->socket_peer_addr.family)
\t\t\tcontinue;

\t\tif (proxy->addr.family == AF_INET &&
\t\t    proxy->addr.in.s_addr == cl->socket_peer_addr.in.s_addr)
\t\t\ttrusted = true;
\t\telse if (proxy->addr.family == AF_INET6 &&
\t\t         !memcmp(&proxy->addr.in6, &cl->socket_peer_addr.in6,
\t\t                 sizeof(proxy->addr.in6)))
\t\t\ttrusted = true;

\t\tif (trusted)
\t\t\tbreak;
\t}
\tif (!trusted)
\t\treturn;

\t/* Duplicate or invalid headers must not override the real peer. */
\tblob_for_each_attr(cur, cl->hdr.head, rem) {
\t\tif (strcmp(blobmsg_name(cur), "x-real-ip"))
\t\t\tcontinue;
\t\tif (forwarded)
\t\t\treturn;
\t\tforwarded = blobmsg_get_string(cur);
\t}

\tif (!forwarded)
\t\treturn;

\tif (inet_pton(AF_INET, forwarded, &addr.in) == 1)
\t\taddr.family = AF_INET;
\telse if (inet_pton(AF_INET6, forwarded, &addr.in6) == 1)
\t\taddr.family = AF_INET6;
\telse
\t\treturn;

\taddr.port = cl->socket_peer_addr.port;
\tcl->peer_addr = addr;
}

static void client_header_complete(struct client *cl)
{""",
        "client.c trusted header handler"
    )
    client = replace_once(
        client,
        "\tif (!rfc1918_filter_check(cl))\n\t\treturn;\n",
        "\tif (!rfc1918_filter_check(cl))\n\t\treturn;\n\n"
        "\t/* Run rebinding protection against the TCP peer before rewriting it. */\n"
        "\tclient_apply_realip(cl);\n",
        "client.c header completion"
    )
    client = replace_once(
        client,
        "\tset_addr(&cl->peer_addr, &addr);\n",
        "\tset_addr(&cl->peer_addr, &addr);\n"
        "\tcl->socket_peer_addr = cl->peer_addr;\n",
        "client.c original TCP peer"
    )
    result["client"] = client

    init = result["init"]
    init = replace_once(
        init,
        "start_instance()\n{",
        """append_realip_proxy() {
\t[ -n "$1" ] && procd_append_param command -J "$1"
}

start_instance()
{""",
        "uhttpd.init proxy list function"
    )
    init = replace_once(
        init,
        '\tappend_bool "$cfg" rfc1918_filter "-R" 0\n',
        '\tappend_bool "$cfg" rfc1918_filter "-R" 0\n\n'
        '\t# Absent or disabled configuration never passes RealIP arguments.\n'
        '\tlocal realip_enabled\n'
        '\tconfig_get_bool realip_enabled "$cfg" realip_enabled 0\n'
        '\t[ "$realip_enabled" = 1 ] && config_list_foreach "$cfg" set_real_ip_from append_realip_proxy\n',
        "uhttpd.init opt-in"
    )
    result["init"] = init

    config = result["config"]
    config = replace_once(
        config,
        "\toption rfc1918_filter 1\n",
        "\toption rfc1918_filter 1\n\n"
        "\t# Trusted X-Real-IP: disabled by default; do not trust arbitrary clients.\n"
        "\toption realip_enabled '0'\n"
        "\t# list set_real_ip_from '192.168.0.251'\n",
        "uhttpd.config disabled default"
    )
    result["config"] = config

    # Validate every upstream anchor before changing any source/package file.
    for key, path in paths.items():
        path.write_text(result[key])
        print(f"Patched {path}")


def main():
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    try:
        patch(Path(sys.argv[1]), Path(sys.argv[2]))
    except (OSError, RuntimeError) as error:
        raise SystemExit(f"RealIP patch FAILED: {error}")


if __name__ == "__main__":
    main()
