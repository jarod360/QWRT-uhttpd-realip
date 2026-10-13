# QWRT uhttpd Real IP

为 uhttpd 增加可信反向代理真实 IP 支持，兼容 `X-Real-IP` 和 `X-Forwarded-For`，供 CGI、Lua/LuCI 通过 `REMOTE_ADDR` 读取客户端地址。

## 安全模型

- 只有 TCP 直接连接来源命中 `set_real_ip_from` 配置的代理，才会读取转发请求头。
- 优先解析唯一的 `X-Forwarded-For` 字段：按代理链从右向左检查，跳过可信代理地址，取第一个非可信地址；不简单取最左侧，降低客户端伪造链前缀的风险。
- `X-Forwarded-For` 缺失、重复、格式非法或整条链都属于可信代理时，回退到唯一且格式合法的 `X-Real-IP`。
- 目前 `set_real_ip_from` 接受单个 IPv4/IPv6 地址，可重复配置；暂不支持 CIDR 网段。
- `X-Forwarded-For` 目前要求只有一个字段值，字段内容可以是逗号分隔的 IP 链；重复字段、空项或非法 IP 会跳过该字段并尝试 `X-Real-IP`，两个头都不可用时才回退到 TCP 对端地址。
- 原始 TCP 对端地址始终单独保存；每个 Keep-Alive 请求都从原始地址重新计算，不继承上一个请求的真实 IP。
- 两个请求头都不可用、或直接连接来源不可信时，继续使用 TCP 原始对端地址。

## QWRT 配置示例

雷池直接连接 OpenWrt，且雷池地址为 `192.168.0.251` 时：

```sh
uci add_list uhttpd.main.set_real_ip_from='192.168.0.251'
uci commit uhttpd
/etc/init.d/uhttpd restart
```

如果请求链路中存在多个受控代理，只有实际可能作为 TCP 连接来源或出现在 `X-Forwarded-For` 链中的代理地址才需要加入可信列表。每个地址重复添加一项。

**重要：** 只添加实际受控的反向代理/WAF 地址。不要添加 `0.0.0.0/0`、整个 LAN 或不受信任的客户端地址。

## 源码基线

- uhttpd: `60f64bec40c8113cf09815ec377761b1f4f95f22`
- OpenWrt build system: ImmortalWrt `v24.10.6`
- CI 工具链映射：`qualcommax/ipq807x`，软件包架构 `aarch64_cortex-a53`

QWRT 使用定制 QSDK 内核和软件包仓库。CI 产物用于验证源码与架构；安装前必须核对设备上的依赖 ABI 和包管理器依赖，不能仅凭 CPU 架构相同就认定完全兼容。
