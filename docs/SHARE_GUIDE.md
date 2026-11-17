# 换个版本能不能用 · 适配手册

拿到包、或者在别的乐跑版本上试之前，看这一页。

---

## 1. 验证范围

| 项 | 值 |
| --- | --- |
| App | `com.lptiyu.tanke` **v4.2.0 / versionCode 220** |
| 系统 | Android 13（SDK 33） |
| 架构 | **arm64-v8a** |
| Root | **Magisk 28.0** |

验证到什么程度：

- sign 算法按「尾盐 / 首盐 / w7 排除集 / v7 排除集 / form-decode」五层拆开，
  逐条与客户端自己算的 sign **逐字符比对**，130 条真实请求 **130/130 命中**
- 请求 AES、`system/update` 响应 AES 都能解得出、改得回、服务端认
- 跑步主链（`Run2/beforeRunV260` → `Run/getTimestampV278` → `Run/stopRunV278`）跑通
- `selftest` **13/13 PASS**

---

## 2. 大概率能用

**同一个乐跑 App 的其它版本，且 < 4.3.0。** 但要先跑一次自检。

核心是「重算 sign」，而 sign 的三个要素（盐、排除集、路径）都可能随版本变。
`adapt-probe` 就是为这件事写的——它在你那个版本上把规则重新推一遍，然后告诉你和 4.2.0 是不是一套。

跳过第 4 节的三步验证，最可能的两种翻车方式：

- 全站「非法请求」→ 什么都点不开
- 只有跑步页报错、首页正常 → 更迷惑，容易以为是网络问题

---

## 3. 一定不能用

| 情况 | 为什么 |
| --- | --- |
| **不是乐跑 App** | sign 规则（盐值、排除集、`V###` 路径）都是这套后端特有的，换任何别的 App 都是 0 命中 |
| **乐跑 ≥ 4.3.0** | 这个版本本来就不需要绕过——服务端 `minVersion` 就是 4.3.0，官方版本直接能跑。装了只是多一层 MITM |
| **非 arm64 设备** | `full` 包里内置的 node 是 arm64 构建，x86 / armeabi-v7a 上跑不起来（`adapt-probe.sh` 会直接报「node 起不来」） |
| **没有 root** | 需要 Magisk 装模块 + `iptables` 改 nat 表 + 写 `/data/adb` |
| **既没有内置 node 也没有 Termux** | 代理本体是个 node 脚本。`full` 包自带 node，`lite` 包需要 Termux 里 `pkg install nodejs` |
| **同时开了别的抓包/代理类 App** | 会抢 `iptables` 的 nat 链或全局代理设置，两边互相打架 |

---

## 4. 拿到别的版本后怎么验（三步）

### 第 1 步：装模块

先在 Termux 运行 `pkg install nodejs`。

**方式 A**：Magisk App 里刷本次提供的 `tanke-proxy-lite.zip` → 重启。
**方式 B（不重启）**：解压后跑 `su -c 'cd <解压目录> && sh deploy.sh'`。

装完先自检，确认模块自己是健康的：

```sh
su -c 'sh /data/adb/tanke-proxy/tanke-proxy.sh selftest'
# 期望最后一行：--- result: ALL PASS ---
```

### 第 2 步：让 App 走一遍，然后跑探测器

**先让 App 正常用一次**（这一步不能省——探测器读的是日志，没流量就没数据）：

```
打开乐跑 → 登录 → 首页 → 跑步页 → 我的
```

然后：

```sh
su -c 'sh /data/adb/tanke-proxy/tanke-proxy.sh adapt-probe'
```

### 第 3 步：看报告

```sh
adb pull /sdcard/adapt-probe-report.txt
```

只看 `[结论]` 和 `[下一步]` 两段。

一致时：

```
[结论]
  全部 18 个端点、136 个请求都命中 4.2.0 的规则
  → sign 规则与 4.2.0 完全一致，可以直接用现有模块。        ← 退出码 0
```

不一致时：

```
[结论]
  12/136 个命中 4.2.0 规则；5 个端点对不上：
    /v3/api.php/Run2/beforeRunV340  (8 次, 一致 0 / 不一致 8)
        期望 P/K/m/D  = 首盐 eFoqdHOdDy6ViJ0i + 键名升序 + 排除{sign,file,mobileDeviceId} + form-decode
        实测 S/K/-/D
[下一步]
  排除集或编码变了（盐对得上）。把上表「实测」与「期望」的差异字母改成 proxy.mjs 的 W7/V7 名单即可。
```

上面这个例子是最典型的翻车方式：路径从 `V260` 变成了 `V340`，模块里 `W7` 名单写的是
`Run2/beforeRunV260`（子串匹配）→ 没命中 → 这个端点掉回普通规则 → sign 错。报告直接把它指出来了。

**判定表**：

| 报告的 `[结论]` | 含义 | 要做什么 |
| --- | --- | --- |
| 「完全一致」 | 规则是同一套 | 直接用，退出码 0 |
| 有端点「不同」，`[下一步]` 说排除集/编码变了 | 盐没变，只是名单或编码不同 | 改 `W7`/`V7` 名单或 `formDecode`，重跑探测直到一致 |
| `[下一步]` 说盐变了 | 首/尾盐不同 | 需要重新逆盐 |
| `[下一步]` 说全局规则对不上 | 盐 / 拼串方式 / 哈希算法变了 | 需要重新逆算法 |
| 大量端点「未判定」 | 缺数据（body 太大、没有 sign、AES 解不开） | 先让 App 多走几个页面；AES 解不开就是算法变了 |

**探测器本身可信吗**：它在 4.2.0 上跑出「一致」（130/130）；把盐换掉、把排除集改掉、
把首尾盐对调，它都能判成「不一致」并指到具体差异位。不会无脑说「一致」。

---

## 5. 报告说「规则不一致」怎么办

先分三种情况。

### (a) 只是名单 / 编码不同（报告已经告诉你差异字母）

不用重新逆向。直接改 `module/proxy.mjs` 顶部：

```
SIGN_SALT        尾盐
SIGN_SALT_W7     首盐
W7               用首盐 + 排除 mobileDeviceId 的端点名单
V7               再排除 nick_name/avatar_url 的端点名单
formDecode()     拼串前怎么解码
```

改完必须做两件事，否则改动会被静默回滚：

1. **改 `MODDIR` 那份**（`/data/adb/modules/tanke_proxy/proxy.mjs`），不是只有运行目录里那份。
   `common.sh:sync_assets()` 会拿 MODDIR 的 md5 覆盖 `PROXY_DIR`，只改后者会被冲掉（这个坑踩过）。
2. **提 `proxy.version`**（比如 `v3.0.0-selfcontained` → `v3.0.1-hotfix`）。
   版本号没变、md5 变了也会被强制覆盖，日志里会出现 `forced in sync`。

然后 `tanke-proxy.sh restart` → `selftest` 必须仍全 PASS → 再跑 `adapt-probe` 直到一致。

### (b) 盐变了 / (c) 拼串或哈希变了

需要重新逆。要准备的东西：

| 要什么 | 从哪来 |
| --- | --- |
| 那个版本的 **dex** | 有 root 的机器：`/data/app/~~*/com.lptiyu.tanke-*/base.apk` 直接拉；或应用商店下同版本 APK。乐跑有壳（`com.secneo.apkwrapper`），要先脱壳才能读到真实常量 |
| 或者**运行时抓包**（客户端原始 body + 它算出的 sign） | 就是本模块的 `capture.jsonl`。只要有它，不改 dex 也能靠枚举把规则试出来——`adapt-probe` 的候选矩阵已经覆盖「盐 × 排序 × 排除集 × 编码」，全不中才需要看 dex |
| 一条能重放的请求 | 4.2.0 的服务端没有 IP 绑定，可以 PC 直连重放做 A/B |

**入口点（4.2.0 的结论，新版本大概率同名）**：

- 算 sign 的函数：`Lg/a0/c/e0/j3/k;->e`（首盐在 `j;->a`，尾盐在 `j;->b`）
- 请求体的加密/解密：同上类族，AES/CBC/PKCS5，base64 每 76 字符插 `\n` 再 urlencode
- `system/update` 响应：另一组 key/iv，外层 `{"is_encrypt":true,"data":"<base64>"}`

---

## 6. 已知限制

| 限制 | 说明 |
| --- | --- |
| **不拦 QUIC / UDP** | 只处理 `tcp/443`。若 App 走了 HTTP/3(QUIC)，那部分流量抓不到也没改。4.2.0 实测走的是 TCP |
| **只拦 `tcp/443`** | 明文 80 端口不拦（API 全在 443） |
| **只拦 3 个域名** | `api2` / `api` / `pre-api` `.lptiyu.com`。换成别的 API 域名就一条都不拦，且**没有任何报错** |
| **只拦乐跑自己** | 靠 `iptables` 按 uid + 目标 IP 重定向，其它 App 完全不受影响。不会设全局 `http_proxy` |
| **CA 必须被 App 信任** | 模块把自带 CA 装进 user store。4.2.0 信任用户 CA。新版本若把「用户 CA」拉黑或上了证书固定，方案直接失效，且表现为 `TLSERR` 而不是「非法请求」 |
| **日志只留 1 份备份** | `capture.jsonl` 到 8 MiB 轮转成 `.1`，旧的直接覆盖 |
| **看门狗 6 次失败会主动放弃劫持** | 故意的：连续重启失败 6 次后摘掉 iptables 跳转，让 App 退回直连（会弹「版本过低」，但至少能用）。所以看到「弹版本过低」先查 `selftest`，别急着重装 |
| **探测器只验 sign** | 不验响应结构、不验接口是否还活着、不验证书信任。这三样靠症状表人工判断 |

---

## 7. 出问题了先跑这两条

```sh
su -c 'sh /data/adb/tanke-proxy/tanke-proxy.sh selftest'      # 模块本身健康吗
su -c 'sh /data/adb/tanke-proxy/tanke-proxy.sh adapt-probe'   # sign 规则还对吗
```

- 两个都 OK 但 App 还是不行 → 不是 sign 的问题，去看 `proxy.out.log` 里的 `ERR` / `TLSERR`（多半是证书或域名）
- `selftest` 有 FAIL → 按 FAIL 那一行修（都是自解释的：全局代理没关、端口没听、心跳过期、两份 `proxy.mjs` 不一致、uid 变了、iptables 规则数不对、看门狗没跑）
- 想彻底停掉：`su -c 'sh /data/adb/tanke-proxy/tanke-proxy.sh stop'`

---

## 8. 关于日志里的账号数据

`capture.jsonl` 里是真实的请求体：`token`（登录态）、`uid` / `student_num` / `school_id`、
`mobileDeviceId` / `mobileModel`、`sign`，以及解密后的整份 JSON。

经本次检查的 lite 候选 ZIP 只包含模块代码、文档和许可，不含证书或日志。以后每次构建仍须单独检查 ZIP 内容；不能据此推断其他 ZIP 安全。

原始请求可能同时出现在 `REQ.bodyText`、`REQ.signTail`、`decrypted`、`REWRITE.from/to`、响应正文和路径查询参数中，加密体也可能携带相同数据。截断日志、只替换明文字段都不足以保证脱敏。不要公开原始抓包、私钥或完整备份；确需分享诊断信息时，逐条审查所有字段和嵌套内容。`adapt-probe-report.txt` 通常是汇总结果，也需检查输入路径、端点和备注。

本次按作者选择保留完整日志行为，未修改运行时代码。

日志位置：

```
/data/adb/tanke-proxy/capture.jsonl        ← 主日志
/data/adb/tanke-proxy/capture.jsonl.1      ← 轮转备份（只留 1 份）
/data/adb/tanke-proxy/proxy.out.log        ← 控制台日志（含路径，一般不含 body）
/data/adb/tanke-proxy/adapt-probe-report.txt
/sdcard/adapt-probe-report.txt
```
