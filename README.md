# QWRT uhttpd RealIP（可信 X-Real-IP）

为 OpenWrt / ImmortalWrt 的 uhttpd 增加 **可信反向代理 X-Real-IP** 支持。LuCI/CGI 等程序可以在有可信代理转发 HTTP(S) 时获取客户端真实 IP。

**RealIP 默认关闭，关闭时保持普通 uhttpd 的源地址行为。** 即使配置中仍留有旧的 `set_real_ip_from`，没有显式打开 `realip_enabled` 就不会信任或解析 `X-Real-IP`。

> uhttpd HTTP 的 X-Real-IP 和 Dropbear SSH 的 Proxy Protocol v2 是两种不同协议。SSH 参见 [QWRT-dropbear-realip](https://github.com/jarod360/QWRT-dropbear-realip)。

## 1. 默认配置

新 IPK 的 `/etc/config/uhttpd` 中，`main` 段增加：

```text
config uhttpd 'main'
    option realip_enabled '0'
    # list set_real_ip_from '192.168.0.251'
```

启动脚本读取 UCI：**仅当 `realip_enabled=1` 时**，才把每条 `set_real_ip_from` 传给 uhttpd 的 `-z` 参数。不提供可信代理时二进制完全忽略 `X-Real-IP`。

旧配置文件如果保留 `list set_real_ip_from`（例如 `192.168.0.251` 和 `192.168.0.254`），由于之前没有 `realip_enabled`，新启动脚本会将缺失值视为 `0`，不会擅自开启。升级已有固件时软件包管理器可能保留旧的 `/etc/config/uhttpd`。

## 2. SSH 命令行开启和关闭

以下命令针对 `uhttpd.main`。如果固件自定义了实例名称，请先用 `uci show uhttpd` 确认。

**检查开关、可信代理列表和进程参数：**

```sh
uci -q get uhttpd.main.realip_enabled || echo 0
uci -q show uhttpd.main.set_real_ip_from
ps w | grep '[u]httpd'
```

**开启 RealIP，设置可信代理**（使用已验证配置中的两个地址，请根据实际反向代理 TCP 来源修改）：

```sh
uci -q delete uhttpd.main.set_real_ip_from
uci add_list uhttpd.main.set_real_ip_from='192.168.0.251'
uci add_list uhttpd.main.set_real_ip_from='192.168.0.254'
uci set uhttpd.main.realip_enabled='1'
uci commit uhttpd
/etc/init.d/uhttpd restart
```

启用后，进程命令行应包含类似 `-z 192.168.0.251 -z 192.168.0.254`。**只有直接连接 uhttpd 的 TCP 对端 IP 命中列表时**，才采纳转发请求头。先处理唯一的 `X-Forwarded-For`，从右向左跳过可信代理，选择第一个非可信 IP；无法解析时再回退到唯一且有效的 `X-Real-IP`。

**关闭 RealIP，恢复普通连接源 IP 行为**（保留可信地址列表）：

```sh
uci set uhttpd.main.realip_enabled='0'
uci commit uhttpd
/etc/init.d/uhttpd restart
```

关闭后重新执行 `ps w | grep '[u]httpd'`，不应出现 `-z` 参数。重新登录 LuCI 验证。若还需要清除旧列表：

```sh
uci -q delete uhttpd.main.set_real_ip_from
uci commit uhttpd
/etc/init.d/uhttpd restart
```

如果当前配置没有 `main` 段，请改用实际的 `config uhttpd` 段名。不要覆盖现有监听地址、证书、LuCI、ubus、timeout 等配置项。

## 3. 可信代理规则及安全边界

- 信任的是**直接连接路由器 uhttpd 的反向代理 IP**，不是客户端 IP。
- `set_real_ip_from` 支持单个 IPv4 或 IPv6 地址；当前版本**不支持 CIDR 或带端口地址**。
- 未启用、无可信代理、TCP 来源未命中，或者 `X-Forwarded-For` 与 `X-Real-IP` 都不可用时，保留真实 TCP 来源 IP。对同一 Keep-Alive 连接的每个请求都会重新计算，不继承上次结果。
- HTTP 请求可伪造 `X-Real-IP` 和 `X-Forwarded-For`：反向代理必须**覆盖**该请求头，不能无条件转发外部客户端传入的同名头；不要信任大网段或未知代理。
- 仅应用层 `REMOTE_ADDR` 等基于 uhttpd 连接地址的数据发生变化，TCP 套接字来源、防火墙和连接路由不会变化。
- `rfc1918_filter` 继续先检查原始 TCP 来源 IP；RealIP 不应绕过 DNS rebinding 保护。
- 开启前先保持一条 SSH 管理连接，以便 LuCI 登录异常时从终端关闭开关。

## 4. GitHub Actions 构建

仓库提供两套独立构建工作流：

- `.github/workflows/build-uhttpd.yml`：ImmortalWrt `v24.10.6` / `aarch64_cortex-a53`。
- `.github/workflows/build.yml`：OpenWrt `openwrt-25.12` / `aarch64_cortex-a53`，在使用 IPK 的兼容构建目标下生成 IPK。

二者均将 uhttpd 源码固定到 `60f64bec40c8113cf09815ec377761b1f4f95f22`，在编译**前**应用 `scripts/apply_patch.py`，修改源码和 IPK 自带的 init/config，最后检查生成的软件包与运行参数。

进入仓库的 **Actions** 页面选择相应工作流运行，构建完成后下载该运行记录的 artifact。**历史 IPK 可能没有开关，不代表已经具备默认关闭行为。**新产物应核实含有 `realip_enabled '0'`、修改后的 `/etc/init.d/uhttpd`、以及可识别的 `-z` 选项。

安装前检查固件 ABI、架构、依赖和包管理器，不要仅凭 `aarch64_cortex-a53` 判断兼容。替换系统 Web 服务可能使 LuCI 暂时断开，推荐先备份 `/etc/config/uhttpd` 并保留 SSH 恢复通道。

## 5. 项目文件

- `scripts/apply_patch.py`：使用先前 realip-dev 的可信 X-Real-IP/X-Forwarded-For 实现，新增 UCI 默认关闭及 init 条件传参，未命中补丁锚点时中止构建。
- `.github/workflows/build-uhttpd.yml`：ImmortalWrt 24.10.6 IPK。
- `.github/workflows/build.yml`：OpenWrt 25.12 IPK。
