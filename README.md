# QWRT uhttpd Real IP

为 uhttpd 增加可信反向代理的 X-Real-IP 支持，供 CGI、Lua/LuCI 通过 REMOTE_ADDR 读取客户端真实地址。

## 安全模型

- 仅接受配置在 set_real_ip_from 中的 TCP 来源地址。
- 仅解析单个、格式严格合法的 IPv4 或 IPv6 X-Real-IP。
- 未配置可信代理、请求头缺失、重复或格式非法时，继续使用 TCP 原始对端地址。
- 每个 Keep-Alive 请求都从不可变的 TCP 原始地址重新计算，不继承上一个请求的真实地址。
- 默认请求头固定为 X-Real-IP，不支持从任意客户端传入的代理链。

## QWRT 配置示例

```sh
uci add_list uhttpd.main.set_real_ip_from='192.168.0.251'
uci commit uhttpd
/etc/init.d/uhttpd restart
```

如果存在多个可信代理，可重复添加 set_real_ip_from。

**重要：** 只能把实际受控的反向代理/WAF 地址加入可信列表。不要把 0.0.0.0/0、整个 LAN 或不受信任的客户端地址加入。

## 源码基线

- uhttpd: 60f64bec40c8113cf09815ec377761b1f4f95f22
- OpenWrt build system: openwrt-25.12
- CI 目标：qualcommax/ipq807x，软件包架构为 ARM64 Cortex-A53

QWRT 使用定制 QSDK 内核和软件包仓库。CI 产物用于验证源码与架构；安装前必须核对设备上的依赖 ABI 和包管理器依赖，不能仅凭 CPU 架构相同就认定完全兼容。
