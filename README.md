# tanke-proxy

一个 Magisk 模块，让**步道乐跑旧版绕过服务端强制更新**，继续正常开跑。
做法是用透明代理**只**劫持这一个 App 的 API 流量，把请求里的版本号改掉，再用真算法重算签名，让服务端认为你在用新版。
适用条件：**root + Magisk + arm64 设备**。

---

## 装

**1. 当前清洗候选提供 `dist/tanke-proxy-lite.zip`**，需要 Termux 中已安装 Node.js。

full 包的安装说明供后续使用：本次未提供或审核 full 实物；补齐运行时、第三方许可并单独检查后，再发布到正式仓库的 Releases。

**2.（二选一）**

```sh
# A) Magisk App：模块 → 从本地安装 → 选 tanke-proxy-lite.zip → 重启，装完即生效

# B) 手工：解压后进目录
su
cd <解压目录>
sh deploy.sh
```

`deploy.sh` 会一次做完：铺文件 → 生成证书 → 装进用户证书库 → 检查依赖 → 启动 → 自检。

**3. 确认装好了**

```sh
su -c 'sh /data/adb/tanke-proxy/tanke-proxy.sh selftest'
```

看到结尾是 `--- result: ALL PASS ---` 且 13 项全 `PASS` 就成了：

```
PASS  node runtime executable (source: termux(...))   PASS  proxy listening on 127.0.0.1:8888
PASS  proxy.mjs present (...)                          PASS  proxy heartbeat fresh (< 150s)
PASS  CA cert + key present (...)                      PASS  MODDIR/PROXY_DIR proxy.mjs identical
PASS  leaf cert for every intercept host (have=3 want=3) PASS  iptables uid matches current app uid
PASS  cert chain verifies against the CA               PASS  rule count matches target IPs (have=2 want=2)
PASS  no system-wide http_proxy (got 'null')           PASS  exactly one OUTPUT jump present
                                                       PASS  watchdog running (pid NNNN)
```

打开乐跑 → 点「开始乐跑」→ 进到安全提示页就是通了。Magisk App 装完记得重启一次，之后开机自动生效。

---

## 卸

```sh
su -c 'sh /data/adb/modules/tanke_proxy/uninstall.sh'
su -c 'rm -rf /data/adb/modules/tanke_proxy'
```

删 iptables 规则、停代理与看门狗、把 `http_proxy` 清回 `null`、删运行状态与日志。
证书材料故意留着（删了下次装得换一套新证书，手机上已信任的那张会失效）；要连证书一起清，
见 [`docs/INSTALL.md`](docs/INSTALL.md) 第 5 节。

---

## 能用在哪

| App 版本 | 状态 |
| --- | --- |
| `com.lptiyu.tanke` **4.2.0**（versionCode 220） | 实测通过，130/130 请求签名逐字符命中 |
| 同一 App 的其它 **< 4.3.0** 版本 | 先跑 `su -c 'sh /data/adb/tanke-proxy/adapt-probe.sh'` 自查，退出码 0 表示规则一致可直接用 |
| **≥ 4.3.0** | 不需要。服务端 `minVersion` 就是 4.3.0，官方版本本身能跑 |
| 别的 App | 不适用。sign 规则（盐、排除集、`V###` 路径）都是这套后端特有的 |

`adapt-probe` 的退出码：`0` 规则一致 / `2` 规则不一致（报告里写了哪几条不对）/ `3` 数据不足（先让 App 走一遍再测）。
诊断与改写方法见 [`docs/SHARE_GUIDE.md`](docs/SHARE_GUIDE.md)、[`docs/VERSION_COMPAT.md`](docs/VERSION_COMPAT.md)。

---

## 常见问题

**装完 App 打不开 / 一直转圈**
代理没起来，但 iptables 还在把请求往 8888 送。跑 `su -c 'sh /data/adb/tanke-proxy/tanke-proxy.sh restart'`；
连续失败 6 次模块会自动摘掉跳转（日志里 `DEGRADED`），此时 App 直连可用。
node 的真实报错在 `/data/adb/tanke-proxy/proxy.out.log`。

**其他 App 会不会断网**
不会。系统级 `http_proxy` 始终是 `null`，只有乐跑的 uid + `api2.lptiyu.com` 的 IP + 443 端口被
REDIRECT 到本机，其它 App 在协议栈层面没被碰过。`selftest` 有一项专门检查这条。

**还是弹「版本过低」**
先 `tanke-proxy.sh status` 看 `listening/healthy`，再 `tanke-proxy.sh iptables` 看是不是 2 条规则 + 1 条跳转。
都有但还是弹，说明规则不匹配了 —— 跑 `adapt-probe` 对一遍。

**想适配别的乐跑版本**
改 `proxy.mjs` 顶部的 `W7` / `V7` 名单和 `formDecode()`，改的是 `/data/adb/modules/tanke_proxy/`
那份（不是运行目录那份，会被覆盖），同时提一下 `proxy.version`，然后 `restart` + `selftest` + 再跑
`adapt-probe`。步骤见 [`docs/SHARE_GUIDE.md`](docs/SHARE_GUIDE.md) 第 5 节。

**日志在哪**
`/data/adb/tanke-proxy/` 下：`boot.log`（开机与看门狗）、`proxy.out.log`（node 控制台）、
`capture.jsonl`（逐条请求，含 `REWRITE` 记录）、`state.env`（当前 uid / IP 快照）。
一次看 60 行：`su -c 'sh /data/adb/tanke-proxy/tanke-proxy.sh log 60'`。

---

## 仓库里有什么

```
module/                  Magisk 模块源码、文档及许可（可直接打包）
  proxy.mjs              透明 MITM + sign 重算 + 响应改写
  gencert.mjs            纯 node:crypto 手写 ASN.1/DER 签 X.509 v3
  common.sh              启停 / 看门狗 / iptables / 证书准备 / 依赖自检
  adapt-probe.mjs        版本自查探测器
  ...
tools/                   发布构建、离线扫描、RUNPATH 改写和本地 TLS 验证
docs/INSTALL.md          装 / 验 / 卸 / 排错（完整版）
docs/ARCHITECTURE.md     数据流、开机流程、稳健性设计、已知边界
docs/VERSION_COMPAT.md   版本敏感常量清单与症状排查表
docs/SHARE_GUIDE.md      换版本怎么验、不一致怎么改
docs/LEAF-CERTS.md       叶证书结构与生成方式
dist/tanke-proxy-lite.zip  轻包（约 74 KB，用 Termux 的 node，不含内置运行时）
CHANGELOG.md             v1 → v3.0.1 演进
RELEASE-HASHES.txt       本次候选 lite 的体积、条目数、SHA256
```

本次候选只含 `lite` 包；需要先在 Termux 里运行 `pkg install nodejs`。请勿把原目录外未检查的 full 包当成本次清洗产物。

---

## 重新打包

Windows PowerShell 5.1 或 PowerShell 7：

```powershell
powershell -NoProfile -File tools/build-packages.ps1 -LiteOnly
python tools/audit-release.py dist/tanke-proxy-lite.zip
```

安装包写入本仓库的 `dist/`；仅打包已声明的模块文件及根许可证，不收集
工作目录、运行日志、证书或备份。`module/` 内有未知文件时构建会失败，需先审查。

full 构建另需 `<仓库>/nrtp/bin/node`、规定的十个动态库、
`nrtp/THIRD-PARTY-NOTICES.txt` 和 `nrtp/licenses/` 中经过核实的上游许可文本；
准备好后运行 `tools/build-packages.ps1`（不加 `-LiteOnly`）。许可文件存在
不代表审查已完成；必须根据实际版本和来源核对。运行时及许可材料不提交到本仓库。

RUNPATH 工具为 `tools/patch-runpath2.mjs`。本次未提供 full 运行时，
未测试 full 构建和 Android 安装。

## 日志与隐私

模块保留原有完整日志行为。`capture.jsonl` 可能包含登录态、个人字段、请求/响应
正文及密文；这些运行时文件不得随源码、安装包或问题反馈公开上传。详见
[分享说明](docs/SHARE_GUIDE.md#8-关于日志里的账号数据)。

## 使用许可

本项目源码公开，采用《免费使用与受限商业分发许可证 v1.0》。

允许个人及组织内部免费使用、学习和修改；允许在保留版权、许可和来源信息的前提下，以非商业目的免费分享原版或修改版。

未经作者事先书面授权，不得售卖本模块、设置付费获取门槛、将其纳入商业产品对外分发，或将其用于提供许可证所限制的收费功能。

完整权利与义务以仓库中的 [LICENSE](LICENSE) 为准。商业授权请通过 LICENSE 中的联系方式联系作者。

Copyright (c) 2026 W。第三方组件分别适用其上游许可，见 [第三方说明](THIRD-PARTY-NOTICES.txt)。

官方仓库：[1683306356/tanke-proxy](https://github.com/1683306356/tanke-proxy)。

授权联系：1683306356@qq.com
