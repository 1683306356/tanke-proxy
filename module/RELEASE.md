# 乐跑 4.2.0 版本门禁绕过 · 发布说明（v3.0.1）

本次清洗候选仅附 lite 包；full 包相关内容为原项目说明，full 实物及其第三方许可尚未提供或审核。

适用 App：`com.lptiyu.tanke`（乐跑）**v4.2.0 / versionCode 220**
模块 id / 目录：`tanke_proxy` / `/data/adb/modules/tanke_proxy`
运行目录：`/data/adb/tanke-proxy`

---

## 1. 这两个包有什么区别

| 包 | 大小 | 里面有什么 | 手机需要什么 |
| --- | --- | --- | --- |
| `tanke-proxy-full.zip` | 见源码仓库发布记录 | 全部文件 + **内置 node 运行时**（`bin/node` + `lib/`） | 只要 root + Magisk |
| `tanke-proxy-lite.zip` | 见源码仓库发布记录 | 全部文件，不含 node | root + Magisk + **Termux 里装 node**（`pkg install nodejs`） |

两个包功能完全一样，`lite` 只是把 node 运行时交给 Termux 提供。
本次未附 full 包；使用当前候选须先安装 Termux 和 Node.js。

---

## 2. 前置条件

| 项目 | 要求 | 怎么确认 |
| --- | --- | --- |
| root | 必须 | `su -c id` 返回 `uid=0(root)` |
| Magisk | 必须，实测 28.0 可用 | `magisk -V` 返回版本号 |
| Zygisk | **不需要**。本模块只用 iptables + 用户证书库，不注入进程、不 hook App | 见下面这条命令的输出可以没有 Zygisk |
| 乐跑 | 已安装，且**已登录**（微信登录） | App 里能进主界面 |
| Termux + node | 只有 `lite` 包需要 | `full` 包不需要，可以没有 Termux |
| 存储空间 | `full` 约 100 MB，`lite` 模块文件不到 1 MiB（另需 Termux/Node.js） | `df -h /data` |

模块不设置系统级 `http_proxy`（保持 `null`），只有乐跑的 uid 被 iptables 重定向，
**其它 App 完全不受影响**。

---

## 3. 安装（三步）

> 下面三步做完，代理就在跑。装完建议重启一次手机，从此开机自动生效。

### 第 1 步：把包放到手机上

当前候选用 lite：先在 Termux 中运行 `pkg install nodejs`，确认 Node.js 可用。

任选一种：

- **A（Magisk App 装，最简单）**
  Magisk App → 底部「模块」→ 右上角「从本地安装」→ 选 `tanke-proxy-lite.zip` → 装完点「重启」。
  重启后模块自动生成证书并启动，跳到第 2 步验证。

- **B（手工解压 + deploy.sh，出问题时修也用这条）**
  ```sh
  adb push tanke-proxy-lite.zip /sdcard/
  adb shell
  su
  mkdir -p /sdcard/tp && cd /sdcard/tp
  # 用任意解压工具解开（MT管理器 / 电脑解压后 adb push 整个文件夹都行）
  sh deploy.sh
  ```
  最后一行 `sh deploy.sh` 会自动：装文件 → 生成证书 → 装证书到用户库 → 检查依赖 → 启动 → 自检。

### 第 2 步：确认成功

`sh deploy.sh` 最后会打印一段 `selftest`。成功的标志是这样（全部 PASS）：

```
--- result: ALL PASS ---
```

Magisk App 安装路径（第 1 步 A）不会打印这段，用第 3 步的命令看。

### 第 3 步：验证命令

```sh
su -c 'sh /data/adb/tanke-proxy/tanke-proxy.sh selftest'
```

成功：结尾是 `--- result: ALL PASS ---`，并且下面这些行都是 `PASS`：

```
PASS  node runtime executable (source: bundled(/data/adb/modules/tanke_proxy/bin/node))
PASS  proxy.mjs present (/data/adb/tanke-proxy/proxy.mjs)
PASS  CA cert + key present (/data/adb/tanke-proxy/ca.crt.pem)
PASS  leaf cert for every intercept host (have=3 want=3)
PASS  cert chain verifies against the CA (gencert verify)
PASS  no system-wide http_proxy (got 'null')
PASS  proxy listening on 127.0.0.1:8888
PASS  proxy heartbeat fresh (< 150s)
PASS  MODDIR/PROXY_DIR proxy.mjs identical (no silent version rollback)
PASS  iptables uid matches current app uid
PASS  rule count matches target IPs (have=2 want=2)
PASS  exactly one OUTPUT jump present
PASS  watchdog running (pid NNNN)
```

失败：任何一行是 `FAIL`，把整段输出和 `su -c 'cat /data/adb/tanke-proxy/boot.log | tail -40'` 一起留着，
对照 §6 处理。

---

## 4. 装完之后怎么用

打开乐跑 → 进主界面 → 点「开始乐跑」→ 进安全提示页即为正常（App 认为你的版本是 4.3.0）。

代理日志里能看到改写动作：

```sh
su -c 'grep -E "REWRITE|RSP 200" /data/adb/tanke-proxy/capture.jsonl | tail -20'
```

`REWRITE` 出现、对应请求 `RSP 200`，说明版本门禁已绕过。

### 常用命令

| 目的 | 命令 |
| --- | --- |
| 看整体状态 | `su -c 'sh /data/adb/tanke-proxy/tanke-proxy.sh status'` |
| 自检 | `su -c 'sh /data/adb/tanke-proxy/tanke-proxy.sh selftest'` |
| 依赖到底缺什么 | `su -c 'sh /data/adb/tanke-proxy/tanke-proxy.sh deps'` |
| 重新生成缺失的证书 | `su -c 'sh /data/adb/tanke-proxy/tanke-proxy.sh certs'` |
| 深度验证证书链 | `su -c 'sh /data/adb/tanke-proxy/tanke-proxy.sh verify-certs'` |
| 重启代理 | `su -c 'sh /data/adb/tanke-proxy/tanke-proxy.sh restart'` |
| 临时关掉 | `su -c 'sh /data/adb/tanke-proxy/tanke-proxy.sh stop'` |
| 看日志 | `su -c 'sh /data/adb/tanke-proxy/tanke-proxy.sh log 60'` |
| 看 iptables | `su -c 'sh /data/adb/tanke-proxy/tanke-proxy.sh iptables'` |
| App 换了新版本，先自查 | `su -c 'sh /data/adb/tanke-proxy/adapt-probe.sh'` |

---

## 5. 卸载

```sh
# 方式一：Magisk App → 模块 → tanke_proxy → 卸载 → 重启

# 方式二：命令行
su -c 'sh /data/adb/modules/tanke_proxy/uninstall.sh'
su -c 'rm -rf /data/adb/modules/tanke_proxy'
# 重启后 Magisk 会清掉模块挂载
```

`uninstall.sh` 会做：删 iptables 规则、停代理进程、停 watchdog、把 `http_proxy` 清回 `null`、
删掉运行状态与日志。

**故意保留的两样**（删了下次装就得换一套新证书，手机上已信任的那张会失效）：

- 证书材料：`/data/adb/tanke-proxy/ca.crt.pem`、`ca.key.pem`、`leafs/`
- 用户证书库里的那张根证书：`/data/misc/user/0/cacerts-added/labca.0`

要彻底清干净，再手工执行：

```sh
su -c 'rm -rf /data/adb/tanke-proxy'
su -c 'rm -f /data/misc/user/0/cacerts-added/labca.0'
```

仅删除本模块创建的证书；不要修改用户证书库中的其他证书。

---

## 6. 常见故障处理

先跑这两条，输出基本就能定位问题：

```sh
su -c 'sh /data/adb/tanke-proxy/tanke-proxy.sh deps'
su -c 'sh /data/adb/tanke-proxy/tanke-proxy.sh selftest'
```

| 现象 | 原因 | 处理 |
| --- | --- | --- |
| selftest: `FAIL node runtime executable (source: missing)` | 装的是 `lite` 包，且没有 Termux/node | 装 `full` 包；或在 Termux 里 `pkg install nodejs` |
| selftest: `FAIL node runtime executable`，deps 显示 `cannot execute` | `bin/node` 在，但 `lib/` 里的 .so 缺了（手工复制漏文件） | 重新解压整包再 `sh deploy.sh`；`su -c 'ls /data/adb/modules/tanke_proxy/lib'` 应有 10 个文件 |
| deps 里 `MISSING leaf certificate for api2.lptiyu.com` | 证书没生成 | `su -c 'sh /data/adb/tanke-proxy/tanke-proxy.sh certs'` |
| deps 里 `MISSING CA certificate` | 首次部署没跑完 / `ca.*.pem` 被删 | `sh /data/adb/modules/tanke_proxy/deploy.sh`（会重建一套） |
| `verify-certs` 报 `signature not made by the CA key` | `ca.key.pem` 和 `ca.crt.pem` 不配对（手工换过其中一张） | 两张一起删掉 → `tanke-proxy.sh certs` → 再把新的 `ca.crt.pem` 覆盖到 `/data/misc/user/0/cacerts-added/labca.0` → 重启 |
| 乐跑提示「当前版本过低」 | 代理没在拦截（多半没证书/没规则），请求打到了真服务器 | `tanke-proxy.sh status` 看 `listening/healthy`；`iptables` 看 2 条规则 + 1 条跳转 |
| 乐跑完全没网 | iptables 重定向到了没起来的端口 | `tanke-proxy.sh restart`；连续失败 6 次模块会自动撤掉跳转（日志里有 `DEGRADED`），此时 App 直连可用 |
| 别的 App 也没网 | 说明又被写入了系统级 `http_proxy` | `su -c 'settings put global http_proxy :0'`，然后 `tanke-proxy.sh restart` |
| 开机后要等一会儿才好 | 开机时 DNS 还没起来 | 正常现象：模块先用缓存的 IP 建规则，网络就绪后自动刷新；watchdog 25 秒一轮 |
| `boot.log` 里反复 `restart failed` | node 起不来或端口被占 | `su -c 'cat /data/adb/tanke-proxy/proxy.out.log | tail -40'` 看 node 的真实报错 |

### 抓完整日志给排查用

日志仅供本机排查。分享前完整审查 `capture.jsonl`、轮转备份、控制台日志和
探测报告中的登录态、个人字段、请求路径查询参数及本机路径。截断行或删除明文字段
不能保证密文里没有相同数据；不要公开原始抓包、私钥或完整运行目录备份。


```sh
su -c 'cp /data/adb/tanke-proxy/boot.log /sdcard/tp-boot.log'
su -c 'cp /data/adb/tanke-proxy/proxy.out.log /sdcard/tp-proxy.log'
adb pull /sdcard/tp-boot.log
adb pull /sdcard/tp-proxy.log
```

---

## 7. 发布物清单

| 文件 | 用途 |
| --- | --- |
| `tanke-proxy-full.zip` | 自包含包（内置 node 运行时），本次未附 |
| `tanke-proxy-lite.zip` | 轻包（用 Termux 的 node），约 74 KiB |
| `RELEASE.md` | 本文件：装 / 验 / 卸 / 排错 |
| `VERSION_COMPAT.md` | 版本敏感点清单：换 App 版本会坏在哪、怎么最快确认 |
| `adapt-probe.sh` + `adapt-probe.mjs` | 版本适配探测器，回答「我手机上这个乐跑版本还能不能用这套模块」 |
| `gencert.mjs` | 证书生成/校验工具（纯 `node:crypto`，手工 DER 编码，无第三方依赖） |

精确体积、条目数与 SHA256 见源码仓库根目录的 `RELEASE-HASHES.txt`；该记录不内置于安装 ZIP。

### 证书是怎么来的

- 本次已检查的 lite 候选包里**没有证书或私钥**（`ca.key.pem`、`ca.crt.pem`、`leafs/` 都不在 zip 里）。
- 第一次部署时在手机上生成：根 CA（`ca.crt.pem` + `ca.key.pem`）+ 每个域名一张叶证书
  （`leafs/api2.lptiyu.com.*`、`leafs/api.lptiyu.com.*`、`leafs/pre-api.lptiyu.com.*`）。
  生成器是包内的 `gencert.mjs`，只用 `node:crypto`，手工做 ASN.1/DER 编码。
- 已经存在的 `ca.key.pem` / `ca.crt.pem` **永远沿用，不重新生成**，所以重装/升级不会让手机
  已经信任的那张根证书失效。
- 根证书装进用户证书库：`/data/misc/user/0/cacerts-added/labca.0`（`system:system` / `644` /
  已 restorecon）。判断「要不要覆盖」用的是**证书指纹**而不是文件字节，
  同一张证书换了 PEM 换行方式不会被重写。

### 两个包的体积构成

- `full`：`bin/node` 51,010,000 B + `lib/` 10 个 `.so` 共 48,170,240 B + 脚本与文档 ≈ 29 KB，
  未压缩合计约 99.2 MB，zip 压缩后约 36 MB。
- `lite`：只有脚本与文档，约 74 KiB。
- `lib/` 是 `bin/node` 的动态依赖全集（`readelf -d` 的 `DT_NEEDED` 闭包）：
  `libz.so.1`、`libcares.so`、`libsqlite3.so`、`libffi.so`、`libcrypto.so.3`、`libssl.so.3`、
  `libicui18n.so.79`、`libicuuc.so.79`、`libicudata.so.79`、`libc++_shared.so`。
  其中 `libicudata` 有 33.5 MB，是体积主因（ICU 数据表）。

### 内置运行时做过的一处修改

Termux 的 `node` 和上面这些 `.so` 都带 `DT_RUNPATH=/data/data/com.termux/files/usr/lib`。
打进包里之前，这个 RUNPATH 被就地改写成 `/data/adb/modules/tanke_proxy/lib`
（写入位置是 ELF `.dynstr` 里该条目指向的那一个字符串，长度不变、文件大小不变）。
改完后 `readelf -d bin/node` 显示新的 runpath，运行时 `/proc/<pid>/maps` 里
`com.termux` 相关映射为 **0** 条。

注意：`node` 的 `.rodata` 里也有一份同样的路径字符串（编进构建配置的 `-L...` 链接参数），
那份**不能动** —— 改动它会让 node 启动时解析内嵌 JSON 失败并直接退出。工具
`tools/patch-runpath2.mjs` 只改 `.dynstr`，就是为了避开这一点。

### 既有验证记录（Android 13 / arm64-v8a / Magisk 28.0）

| 项 | 做法 | 结果 |
| --- | --- | --- |
| 无 Termux 可用 | 把 Termux 的 `node` 改名（`node.bak`），重启代理 | 起得来，`exe=/data/adb/modules/tanke_proxy/bin/node`，`termux mappings=0`，selftest 13/13 PASS |
| 现有 CA 不被覆盖 | 记录 `ca.crt.pem`/`ca.key.pem`/`labca.0` 的 sha256 → 重跑 deploy → 再比 | 三个哈希全部不变；deploy 输出 `CA present, kept unchanged` |
| 从零生成 | 在临时目录跑 `gencert ensure`（CA + 3 张叶证书）+ `gencert verify` | 三个域名 TLS 握手全部通过 |
| lite 能装能跑 | 删掉 `bin/`+`lib/`，解压 lite 包跑 `deploy.sh` | 回退到 Termux node，selftest 13/13 PASS |
| full 能装能跑 | 解压 full 包 → `sh deploy.sh`；另用 `magisk --install-module` 走 Magisk 安装路径 | 两条路径都成功；Magisk 路径会暂存到 `/data/adb/modules_update/`，重启生效 |
| 乐跑链路 | 冷启动 App | 167 次 TLS 全部 `TLS_OK`、`REWRITE` 167、`RSP 200` 167、`ERR` 0，含 `system/update` 的 `REWRITE_RSP`（233/230 → 220/220） |

### 复测提示（v3.0.1）

v3.0.1 只修了一处**报表缺陷**，运行时行为与 v3.0.0 完全一致：

- 根因：`common.sh` 的 `log()` 用**全局变量 `n`** 统计 `boot.log` 行数，而 `apply_iptables()`
  又拿 `n` 当规则计数器。循环里 `n=$((n+1))` 之后紧接着调 `log`，计数器被覆盖成日志行数，
  于是 `state.env` 里的 `rules=` 写成了 `820`（当时 `boot.log` 的行数），真实规则只有 `2` 条。
- 修法：`log()` 改用函数内 `local _logn`；`apply_iptables()` 的计数器也声明成 `local`。
  **没有任何代码读 `rules=` 这个字段**（selftest 用的是 `iptables -t nat -S` 的实际条数），
  所以这是纯报表错误，升级不改变任何行为。
- 升级后自检：`cat /data/adb/tanke-proxy/state.env` 应为 `rules=2`，且等于
  `iptables -t nat -S TANKE_PROXY | grep -c -- "-A TANKE_PROXY"`。
- `selftest` 的 `version:` 行显示的是 `proxy.version`（即 `proxy.mjs` 的版本，原版 v3.0.1 未修改运行逻辑；
  本候选仅清洗一处注释，版本标记仍是 `v3.0.0-selfcontained`）；模块自身版本看
  `/data/adb/modules/tanke_proxy/module.prop` 的 `version=v3.0.1` / `versionCode=301`。
- 证书不会因为升级而重生成：`up()` 根本不碰证书，`ensure_certs()` 对已存在的 CA 只打印
  `cert: CA present, kept unchanged`。升级前后 `ca.crt.pem` 与 `labca.0` 的 md5 必须一致。

**想验证「证书是自动生成」的话，需要先把旧状态挪开**：
`/data/data/com.termux/files/home/tanke-proxy`（v2 遗留目录）存在时，`deploy.sh` 会按设计
从那里迁移旧 CA，并打印
`migrated ca.crt.pem from /data/data/com.termux/files/home/tanke-proxy (keeping the trusted CA)`。
看起来像"没有生成新证书"，其实是在复用。要复测生成逻辑，先把这个目录挪开再跑 `deploy.sh`：

```bash
su -c 'mv /data/data/com.termux/files/home/tanke-proxy /data/data/com.termux/files/home/tanke-proxy.bak'
su -c 'sh /data/local/tmp/tp/deploy.sh'      # 这次会真的生成 CA
```

还要注意：CA 装进用户证书库的文件名**固定是 `labca.0`，不是随机 hash** ——
完整路径 `/data/misc/user/0/cacerts-added/labca.0`。所以「`labca.0` 不存在」只说明没装进去，
不代表证书没生成；反过来「文件名没变」也不代表没重新生成。判断有没有重生成，比
`ca.key.pem` 的 md5 最直接（`md5sum /data/adb/tanke-proxy/ca.key.pem`）。


---

## 8. 换 App 版本时先跑这一步

模块只对 `com.lptiyu.tanke` 的 4.2.0 验证过。换版本后：

```sh
su -c 'sh /data/adb/tanke-proxy/adapt-probe.sh'
```

- 退出码 `0` + 报告 `sign 规则与 4.2.0 一致` → 现有模块可直接用。
- 退出码 `2` → 规则不一致，报告里写了哪几条不对，按 `VERSION_COMPAT.md` 逐项对。
- 退出码 `3` → 数据不足（日志太旧或还没有流量），按提示让 App 走一遍再测。

报告位置：`/data/adb/tanke-proxy/adapt-probe-report.txt`，同时复制到 `/sdcard/adapt-probe-report.txt`。

以上为原项目保留的历史验证记录；本次仅清洗发布文件，未进行新的真机测试。
