# 架构与稳健性设计

目标 App：`com.lptiyu.tanke`（乐跑）v4.2.0 / versionCode 220。
本文件说明流量怎么被接住、为什么这样做，以及各处故障是怎么处理的。

---

## 1. 为什么不用全局 `http_proxy`

v1 的做法是每次开机执行 `settings put global http_proxy 127.0.0.1:8888`。
这是**系统级**代理：手机上每一个 App 的 HTTP(S) 都先连 `127.0.0.1:8888`，
代理只要有一点处理不过来，全机断网。实测 v1 的 `proxy.out.log`：

| 现象 | 计数 |
|---|---|
| `CONNECT data.lptiyu.com`（媒体 CDN，本不该拦截） | 30,718 次 |
| `ERR ... getaddrinfo ENOTFOUND api2.lptiyu.com`（root 进程 DNS 不稳） | 21 次 |
| 真正到达业务层的 `REQ` | 203 次 |

单线程 node 被 3 万次重连压住 → 其它 App 全部表现为「断网」。

**本方案的前提：系统的 `http_proxy` 永远是 `null`。** 改用 iptables 只劫持
乐跑这一个 uid 发往 `api2.lptiyu.com` 的 443，其它 App、其它域名在协议栈层面没被碰过。

---

## 2. 拦谁

实测 `capture.jsonl` 全量统计：

| 域名 | 角色 | 命中数 |
|---|---|---|
| `api2.lptiyu.com` | **业务 API + 版本闸门**（`/v3/api.php/system/update`、`Run2/beforeRunV260` 等全在这） | 734 |
| `data.lptiyu.com` | 纯媒体（APK / 图片 CDN），不需要也不应该拦截 | 30,718 |
| `pre-api.lptiyu.com` | 生产流量 0 命中，未使用 | 0 |

→ 只拦 `api2.lptiyu.com`。媒体流量走原生直连，v1 那 3 万次重连风暴从原理上消失。

---

## 3. 数据流

```
                    ┌─────────────── 手机 ───────────────┐
 乐跑(uid NNNNN) ──443──▶ iptables nat OUTPUT ──▶ TANKE_PROXY 链
                           │  匹配: owner uid==<App uid> AND dst∈{api2 IPs} AND dport==443
                           │  动作: REDIRECT --to-ports 8888
                           ▼
                     127.0.0.1:8888  node proxy.mjs（透明 TLS，无需 CONNECT）
                           │  1. 读 ClientHello → 解 SNI
                           │  2. api2 → 用本机 CA 现签叶证书做 MITM
                           │  3. 改 version / version_name → 用真算法重算 sign
                           │  4. 转发到**已钉死的 IP**:443（servername 带 SNI）
                           │  5. system/update 响应改写成「已是最新」
                           ▼
                     api2.lptiyu.com:443
```

关键点，逐条对应 v1 的三个坑：

| v1 的问题 | 现在的做法 |
|---|---|
| 全局 http_proxy 劫持全机 | iptables 按 `-m owner --uid-owner` + 目标 IP 过滤，只匹配乐跑 |
| `CONNECT` 打头会丢掉紧跟的 ClientHello，TLS 握手失败 | **透明模式**：连进来就是 TLS，没有 `CONNECT` 这一层 |
| root 进程 `getaddrinfo` 偶发 `ENOTFOUND`（21/203） | 上游**按 IP 直连**（`host=IP, servername=域名`），运行时零 DNS 依赖 |
| 媒体域名被一起劫持，3 万次重连 | 媒体域名**根本不进规则**，原生直连 |

代理以 **root(uid 0)** 运行，而规则只匹配 App 的 uid，所以代理自己的出站连接
不会被自己的规则二次劫持，不存在回环。

---

## 4. 落地清单

| 路径 | 作用 |
|---|---|
| `/data/adb/modules/tanke_proxy/` | Magisk 模块目录：`service.sh` `uninstall.sh` `common.sh` `resolve4.mjs` `proxy.mjs` `gencert.mjs` `proxy.version` `module.prop` |
| `/data/adb/tanke-proxy/` | 运行目录：`proxy.mjs`、`targets.env`（钉死的 IP）、`ca.crt.pem`、`ca.key.pem`、`leafs/`、`capture.jsonl`、`proxy.out.log`、`boot.log`、`state.env` |
| `/data/misc/user/0/cacerts-added/labca.0` | 已被系统信任的本机 CA（用户证书库） |

`targets.env` 内容就是两行公开 DNS 记录：

```
api2.lptiyu.com=180.76.199.204
pre-api.lptiyu.com=47.96.27.222
```

---

## 5. 开机流程（`service.sh`）

1. 等 `sys.boot_completed=1`，再等 3 秒
2. `ensure_no_global_proxy` —— 清掉一切残留的全局代理（v1 的病灶，每次开机都要确认它没回来）
3. **先用 `targets.env` 缓存把规则装上**（保证开机就能连），再解析、再按需重建
4. `resolve_targets`：先走自建 UDP DNS（`resolve4.mjs`，直接问 `192.168.1.1 / 114.114.114.114 / 223.5.5.5`），
   失败退回 `ping`，**再失败就沿用上次缓存的 IP**，绝不因为解析失败丢规则
5. `sync_assets`：模块里的 `proxy.mjs` / CA 与运行目录比对**版本号 + md5**，不一致强制覆盖
6. `start_proxy`：`setsid node proxy.mjs`，监听 `127.0.0.1:8888`
7. `apply_iptables`：**先 `-F` 整条链再重建**，反复重启不累积规则
8. 起看门狗（25 秒一轮）

实机 reboot 后的日志：

```
[18:59:14] service.sh start (per-app, watchdog 25s)
[18:59:32] boot: cached targets present -> installing rules first
[18:59:32] boot: rules installed from cache (2 rules)
[18:59:54] targets: api2 unresolved, kept cached ...        <- 此刻 DNS 还没就绪
[19:00:00] proxy: UP on 127.0.0.1:8888 ver=... (pid 7598 after 3s)
[19:00:01] service.sh READY uid=NNNNN ver=...
```

开机后约 16 秒规则已可用，25 秒内完整 READY；DNS 未就绪也不影响。

幂等性：`TANKE_PROXY` 链每次整条 flush 后重建，`OUTPUT` 里的跳转先 `-C` 查重。
连做 3 轮 stop/start 恒定 3 条（2 REDIRECT + 1 跳转），不累积。

---

## 6. 稳健性设计

### 6.1 代理进程挂了会怎样

`kill -9` 之后 iptables 仍然把每个 api 请求 REDIRECT 到 8888。修复前看门狗周期 300 秒，
用户看到的是「接口全挂」，最长持续 5 分钟。现在两条：

**(1) 看门狗 300s → 25s，活体判定不只看端口。** 端口在听不代表进程能干活（僵死进程照样持有
listening socket）。双判据：`LISTEN` 行存在 **且** 心跳文件 mtime 距今 ≤150 秒。
代理侧每 30s `utimes()` 一下 `$PROXY_DIR/.heartbeat`（写文件太贵，改时间戳）。

```
=== kill -9 之后 ===
t+2s:  healthy=n listening=n
t+7s:  still down      t+12s: still down      t+17s: still down
RECOVERED at t+22s by watchdog (new pid 21830)      <-- 原来最长 300s
```

**(2) 反向保护：连续起不来就主动放弃劫持。** 连续失败 `FAIL_LIMIT=6` 次（约 2.5 分钟）就
**只删 OUTPUT 跳转**（链内容留着，方便恢复），App 退回直连，能上网但「版本过低」回来了：

```
heal#1..5  fails=1..5  hijack=on   jump=present
heal#6     fails=6     hijack=off  jump=absent    degraded=yes
  direct reachability: OK
```

### 6.2 看门狗不能只活在 `service.sh` 里

手动 `tanke-proxy.sh restart` 之后原先根本没人看门。现在循环体收进 `common.sh::watchdog_loop()`，
`up()` 结尾调 `ensure_watchdog()`，`down()` 调 `stop_watchdog()`，pid 文件每 tick 复核，
新看门狗会顶掉旧的（不会两个抢着重启代理）。

### 6.3 `proxy_pids` 从 18 秒降到 0 秒

原实现对**每个 PID** fork 一个 `tr` 读 cmdline，手机上几百个进程：

```
改前: stop_proxy = 16s   start_proxy = 34s   proxy_pids = 18s     (restart 67s)
改后: stop_proxy = 1s    start_proxy = 3s    proxy_pids = 0s      (restart ~12s)
```

改成一次 `grep -l -a` 扫完再校验候选，并要求 `argv[0]` 是 `node`
（避免把命令行里恰好提到 `proxy.mjs` 的 shell 当成代理）。

### 6.4 IP 变化 / 多 A 记录

`api2.lptiyu.com` 目前只有 1 条 A 记录，所以「只钉一条」不构成隐患。
解析器本身能收全多条，多 IP 会**逐个展开成独立 iptables 规则**
（实测：伪造 2 条 A 记录 → 3 条链内规则，恢复后回到 2 条）。
看门狗每 5 分钟重解析一次，只有 IP 集合真的变了才重建；解析失败**保留上一份缓存**：

```
[19:59:54] targets: api2.lptiyu.com unresolved, kept cached api2.lptiyu.com=180.76.199.204
```

另修一处白等：`dumpsys connectivity` 列出的首个 DNS 是 IPv6，udp4 socket 对它必然超时 2.5s。
`resolve4` 现在只保留 IPv4 解析器：**解析耗时 5s → 0s**。

### 6.5 uid 变了（卸载重装）

`tanke_uid()` 实时 `stat`，`heal()` 每 tick 比对「state 里记录的 uid」和「当前 uid」，不一致就重建：

```
faked state -> rules uid=<应用UID>
heal -> log: iptables: + uid NNNNN -> 180.76.199.204:443
after heal: rules uid=NNNNN  uid_ok=YES  rules=2
```

App 没装（取不到 uid）时写 `heal: WARN com.lptiyu.tanke not installed (no uid)`，不静默。

### 6.6 日志不无限增长

- `capture.jsonl` 由 node 自己轮转，上限 **8 MiB**，**按真实文件大小判断**（原先只算进程自己写过
  的字节，实测 9.6 MB 都不触发），触发后写一条 `LOG_ROTATE`；
- `proxy.out.log` 由 `common.sh::rotate_out_log()` 做 **copytruncate**（上限 4 MiB）——
  用 `renameSync` 会让 shell 的 `>>` fd 指向被重命名的 inode，新文件永远为空；
- `boot.log` 保持 4000 行封顶，超了砍一半。

### 6.7 代理自身

- 单个畸形连接不拖垮进程：空载荷 / `GARBAGE` / 20 个并发垃圾连接后，`pid` 不变、`fd=20`、`threads=11`。
- **连接上限** `server.maxConnections = 128`。200 并发冲击实测：
  `fds 20 -> 148（=128 上限 + 20 基础）-> +25s 73 -> +35s 回到 20`，无泄漏。
  依赖新加的 30s idle timeout + 响应后 `destroySoon()`（原先只 `end()` 半关闭，卡住的连接永久占 fd）。
- **信号免疫**：node 收到 `SIGUSR2/SIGUSR1` 会启 inspector 然后退出，实测一次误发 `kill -USR2`
  直接把代理打死。现在这两个信号被忽略（`SIGTERM` 保持默认，`stop_proxy` 仍有效）。
- **崩溃不再「假活」**：原先 `uncaughtException` 只记日志不退出，进程可能半死不活但还占着端口，
  看门狗误判健康。现在连续 5 次致命异常主动 `exit(1)`，交给看门狗起一个干净进程。

### 6.8 两份 `proxy.mjs` 静默回退

设备上跑的和打包用的可能是不同版本，而 `sync_assets()` 只比 `proxy.version` 会让重装**悄悄降级**。
现在同时比版本号和 **md5**，不一致强制用模块目录那份覆盖：

```
[18:45:05] assets: proxy.mjs forced in sync (ver A->B md5 xxx->yyy)
```

`start_proxy()` 每次启动打印 `ver=... md5=前8位`，`selftest` 有专门一条
`MODDIR/PROXY_DIR proxy.mjs identical (no silent version rollback)`。

### 6.9 性能基线

| 指标 | 空闲 | 200 并发冲击后 |
|---|---|---|
| RSS | 55.1 MB | 55.9 MB（不增长） |
| 线程 | 11 | 11 |
| fd | 20 | 148 峰值 → 35s 回落到 20 |
| CPU | 5 秒内 utime 不变 | 200 连接 / 8s，累计约 0.43s |

端到端延迟（`capture` 里 `RSP.ms`）：`getIp 210ms`、`RefreshToken 173ms`、
`getAllSchoolAdvertise 171ms` —— 与直连同一量级，MITM 没有明显加价。

---

## 7. 已知边界

- **只覆盖 TCP/443**。App 若有明文 HTTP(80) 请求，不会被改写，也不会被破坏（走原生直连）。
- **QUIC/UDP 443 不拦**。若 App 某天改用 HTTP/3，该请求会绕过改写直连服务端。
  `api2` 目前是 HTTP/1.1 over TLS，实测 `/proc/net/udp{,6}` 里 `:443` 没有任何 socket。
  哪天又弹「版本过低」，第一件事是查是不是走了 QUIC：
  ```sh
  su -c "awk 'NR>1{split(\$2,a,\":\"); if(a[2]==\"01BB\") print}' /proc/net/udp /proc/net/udp6"
  ```
- **不碰 `/data/data/com.lptiyu.tanke`**，不 `pm clear`，不卸载，不改 APK。
- `nat OUTPUT` 里那两条 `DNAT → 127.0.0.1:29xxx/31xxx` 是 **vivo 系统自己的**
  （指向 `com.vivo.daemonService` / `com.vivo.abe`，端口每次重启都变），不是本方案的残留。
- `timestamp` 参与签名。若出现「非法请求」，除了查出口 IP 也要查系统时间是否被手动改乱。

---

## 8. 套用到别的 App

改三处：`common.sh` 的 `PKG`（uid 自动取）、`refresh_targets()` 里的 hosts、
`proxy.mjs` 的 `INTERCEPT_RE`（也可用环境变量 `INTERCEPT_RE` 覆盖）。

但**版本门 / sign 重写规则（`resignBody` / `rewriteUpdateResponse`）是乐跑 4.2.0 特有的**，
换 App 必须重新逆向它的签名算法与 param 顺序，不能直接套。
换一个**乐跑版本**（同一个 App）则先用 `adapt-probe` 自查，见 [`VERSION_COMPAT.md`](VERSION_COMPAT.md)。

---

## 9. 本轮修复的代价（如实写）

| 代价 | 说明 | 取舍 |
|---|---|---|
| 看门狗每 25s 醒一次 | 每次约 1-2s（`iptables -S` + `-C` + stat），一天约 3400 次唤醒 | 换成 60s 会让故障窗口回到 1 分钟；实测对续航无感（sleep 25 里绝大部分时间是睡眠） |
| 30s idle timeout | 慢请求（>30s 无数据）会被切断 | 接口都是秒级；换来 fd 不会被异常客户端钉死 |
| 失败 6 次后主动退回直连 | 配置错时会「悄悄」变回版本过低 | 有意为之：能上网 > 完全不能用；`degraded=yes` 写进 `health.env`，`status` 可见 |
| `capture.jsonl` 只留 1 份 `.1` | 更早的请求明细会被覆盖 | 上限 8 MiB ≈ 2 周日常流量；要长期留存就调大 `MAX_CAPTURE` |
