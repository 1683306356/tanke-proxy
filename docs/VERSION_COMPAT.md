# 版本敏感点清单（VERSION COMPAT）

> 适用对象：当前清洗候选 `dist/tanke-proxy-lite.zip`（模块 `tanke_proxy` v3.0.1）；full 包未附。
> 已验证版本：`com.lptiyu.tanke` **v4.2.0 / versionCode 220**（v3.0.0 发布时在真机复验过）
> 本文回答一个问题：**把这个模块换到另一个乐跑版本上，会坏在哪、怎么最快确认。**

---

## §0 探测器靠什么工作（前置结论）

写探测器之前先确认了一件事：**代理日志里到底有没有「客户端原始的 body」**。
结论：**有，而且不需要改协议逻辑就能拿到。**

| 问题 | 结论 | 证据 |
| --- | --- | --- |
| 日志里有客户端原始 body 吗 | **有** | `REQ` 记录在**改写之前**就写入，`REQ.bodyText` 是客户端发来的原样字节（≤8000 字符，且要求 body < 20000 字节） |
| `REWRITE` 记录里有 before/after 吗 | **有，但原来被截断到 400 字符** | v2.3 的 `REWRITE.from/to` 用 `slice(0, 400)`；加密体 `key=…` 有 700+ 字符 → 只留半截密文，事后无法复核 |
| 探测器的数据源 | **`REQ.bodyText`** | 130/130 条请求都能从 `REQ` 拿到完整体；`REWRITE` 只当交叉校验 |

**为什么必须用 `REQ` 而不是 `REWRITE`**：sign 是客户端用**它自己发出去的那份数据**算的。
`REWRITE` 里那份是代理改过 `version_name`/`version` 之后重新算的 sign，
拿它去验证「客户端的规则」等于自己证明自己。

**v2.3.1 为此加了两处日志（v3.0.0 原样保留）**（都是纯增量，不改任何协议行为）：

| 改动 | 位置 | 作用 |
| --- | --- | --- |
| `REQ.signTail` | `proxy.mjs:583-597`（字段在 `:594`） | 只在「`bodyText` 丢信息」时写 body 末尾 600 字符。`sign` 一般排在表单最后，body ≥ 8000 字符被截断时正好把它切掉。正常流量不触发（实测 0 条），日志不膨胀 |
| `REWRITE.from/to` 400 → 3000，新增 `enc`/`fromLen`/`toLen` | `proxy.mjs:612-622` | 加密体也能完整留档，做 A/B 时不用重抓 |

改动后复验：`tanke-proxy.sh selftest` **8/8 PASS**，代理重启后新流量 6 条 REQ 全部正常（`RSP 200`，`ERR` 计数 0）。

---

## §1 版本敏感常量清单

「敏感度」定义：

- **高** = 一变就大面积失败（全站 sign 挂 / 核心功能断）
- **中** = 部分端点失败，或功能降级但还能用
- **低** = 不影响主链
- **未知** = 没有证据能判断，必须拿到那个版本才能定

| # | 名字 | 当前值 | 位置（`proxy.mjs`） | 敏感度 | 判断依据 |
| --- | --- | --- | --- | --- | --- |
| 1 | 尾盐 | `rDJiNB9j7vD2` | `:30` `SIGN_SALT` | **高** | 拼串的最后一段，所有非 w7 端点都用它。服务端拿同一个常量重算，改一个字节 → 全站 `{"status":0,"info":"非法请求"}` |
| 2 | 首盐 | `eFoqdHOdDy6ViJ0i` | `:31` `SIGN_SALT_W7` | **高** | 影响面限于 w7 名单，但 w7 里含 `Run2/beforeRunV260`（跑步主链）和 `Login/quickLoginV339`（登录）→ 实际等于核心功能全挂 |
| 3 | w7 名单 | 8 条路径（见下） | `:34-35` `W7` | **高** | 它同时决定「用首盐还是尾盐」和「排不排 `mobileDeviceId`」。名单漏一个/多一个 → 该端点 sign 必错。**而且是按路径子串匹配**，路径里的 `V###` 一变，匹配也一起失效 |
| 4 | v7 名单 | `Login/quickLoginV339` | `:36` `V7` | **中** | 只影响一个端点；坏了表现为「登录失败」，其它页面照常 |
| 5 | v7 额外排除字段 | `nick_name`、`avatar_url` | `:59` `SKIP_V7` | **中** | 同上。4.2.0 实测依据：连续 6 次 `quickLoginV339` 原始 sign 用「排除这两个字段」规则 6/6 命中，不排除则服务端回非法请求 |
| 6 | 拼接骨架 | 键名 ASCII 升序，`键名+值` 直接拼、**无分隔符** | `:72-79` `signFor()` | **高** | 算法骨架。变了就是「连无盐都算不出来」。变化概率不高（同一套后端不太会重写），但一旦变就得重新逆向 |
| 7 | 加密体 AES key | `goMEzJ1pDpncNHb9` | `:32` `AES_KEY` | **高** | `Run2/beforeRunV260`、`Login/RefreshToken`、`report/getOssSts` 的请求体全靠它。解密失败 → 无法改 version → 服务端按 4.2.0 拦；再加密失败 → 请求体直接是坏的 |
| 8 | 加密体 AES iv | `ZUrAS2lUidjyY2gK` | `:33` `AES_IV` | **高** | 同上（CBC 固定 iv，两个常量是一体的） |
| 9 | 响应 AES key | `Wet2C8d34f62ndi3` | `:39` `RSP_KEY` | **高** | 只用于 `system/update` 响应。但**它的失效会阻断整个 App**：解不开就没法把 `min_version` 改小，客户端拿自己的 220 跟服务端的 230 比 → 弹「您当前版本过低」并挡住使用 |
| 10 | 响应 AES iv | `K6iv85jBD8jgf32D` | `:40` `RSP_IV` | **高** | 同上 |
| 11 | 改写目标 version_name | `4.3.0` | `:37` `TARGET_VN` | **高** | 这是**跟着服务端走**的值，不是跟着客户端走。服务端 `minVersion` 一提（比如 4.4.0），4.3.0 也会被拦 → 必须同步抬。**这是最容易失效的一项** |
| 12 | 改写目标 versionCode | `233` | `:38` `REWRITE_VERSION` | **高** | 同上，与 `min_version=230`/`max_version=233` 成对 |
| 13 | 「假装已是最新」的值 | `220` / `4.2.0` | `:41-42` `LIE_VERSION` / `LIE_VN` | **中** | 只影响 `system/update` 改写结果。若客户端换了比较字段（比如改看 `versionName`），要跟着改；解不开时的兜底依然是「弹更新」 |
| 14 | `system/update` 响应字段名 | `max_version`、`min_version`、`versionCode`、`versionNumber`、`url`、`versionName` | `:100-123` `rewriteUpdateResponse()` | **中** | 字段改名 → 改写写到不存在的键上 → 等于没改。注意 4.2.0 是 `is_encrypt` + `data` 包一层密文的结构，外层结构也可能变 |
| 15 | 明文表单的编码处理 | 拼串前 `form-decode`（`%XX` 还原、裸 `+` → 空格） | `:67-71` `formDecode()` | **中** | 这是**客户端行为**（`java.net.URLEncoder` 编，服务端 `$_POST` 解）。若新版本换编码器或改成不编码 → 拼串输入不同。4.2.0 的硬证据：不解码时 `Run/getTimestampV278`（`point_ids=<点位列表>`）和 `Report/appLog`（`fileName=Public/Upload/...`）回非法请求，解码后正常 |
| 16 | 拦哪些域名 | `^(api2\|api\|pre-api)\.lptiyu\.com$` | `:182` `INTERCEPT_RE` | **中** | 只影响「拦不拦」。但若新版本改用别的 API 域名（如 `api3.lptiyu.com`），就是**一条都不拦**，模块完全失效且没有任何报错。反过来说放宽它也有代价：全量劫持 `data.lptiyu.com` 会打坏图片（曾实测 2343 CONNECT / 1457 TLSERR） |
| 17 | iptables 劫持范围 | `uid + 目标 IP(2 个) + tcp/443` | `common.sh` `apply_iptables()` | **低** | 与 App 版本无关，只跟 uid 和目标 IP 有关（重装会换 uid，已有自愈；IP 会变，已有多 A 刷新） |
| 18 | CA 与信任链 | 部署时生成或沿用设备 CA，再装进 user store | `common.sh` `sync_assets()` | **低**（对模块自身）/ **未知**（对目标 App） | 模块侧是稳定的。但**新版本 APK 是否还信任用户 CA**，只有把它拆开看 `res/xml/network_security_config.xml` 才知道 |
| 19 | 目标版本是否存在 `network_security_config` 收紧（用户 CA 被拉黑 / 只信任 system CA） | — | 不在 `proxy.mjs` 里 | **未知** | 4.2.0 信任用户 CA（这是整套方案能跑的前提）。4.3.x 之后厂商收紧 NSC 是很常见的操作，但**我没有任何 4.3.x 的样本，不敢猜成高或低**。要判断只能：拿到那个 APK → 解 `res/xml/network_security_config.xml` → 看有没有 `<certificates src="user"/>` 或对 `api2.lptiyu.com` 的 `pin-set` |
| 20 | 服务端是否额外校验 UA / 自定义头 / 设备指纹 | 4.2.0 未见 | 不在 `proxy.mjs` 里 | **未知** | 4.2.0 上服务端只用 `sign` + 明文里的 `version*` 卡版本，没有 IP 绑定（可 PC 重放做 A/B，已验证）。新版本是否加了别的门（比如 `mobileDeviceId` 绑定），没有证据 |

### w7 / v7 名单原文

```
w7（首盐 + 排除 mobileDeviceId）
  Login/quickLoginV339   Login/RefreshToken   Run2/beforeRunV260   Run/stopRunV278
  Run2/gyroscope         Run/setRunLocationRecord
  Report/getOssSign      report/getOssSts            ← 注意大小写不统一，原样照抄

v7（= w7 再排除 nick_name / avatar_url）
  Login/quickLoginV339
```

---

## §2 带 `V###` 后缀的接口路径

> **先说一个反直觉但很关键的事实：`V###` 不是 App 的 versionCode。**
> 4.2.0 的 `versionCode` 是 **220**，但它调用的接口里带着 `V260`、`V276`、`V278`、`V300`、`V330`、`V339`。
> 所以 `V###` 是**服务端 API 的世代号**，跟客户端版本号没有换算关系，
> **不能靠「App 从 4.2.0 升到 4.3.0」去推接口会变成什么** —— 只能从新 APK 的 dex 里读。

三源交叉的图例：

- `静态` = 串池/dex 里存在（`unpack/strings_all.txt`、`unpack/classes_all.txt`，与 `static2/t2b_fragments.md` 的 60 模块 311 方法表一致）
- `日志` = 代理日志里**真实抓到过**（`REQ.path`）

### 已适配路径里出现过的（日志 + 静态都有）

| 模块 | 路径 | 静态 | 日志 | 备注 |
| --- | --- | --- | --- | --- |
| Run2 | `Run2/beforeRunV260` | ✔ | ✔ 14 次 | **w7 端点**（首盐）；跑步主链，坏了直接跑不了 |
| Login | `Login/quickLoginV339` | ✔ | ✔ | **w7 + v7 端点**；登录 |
| Login | `Login/RefreshToken` | ✔ | ✔ 6 次 | w7 端点；加密体 |
| report | `report/getOssSts` | ✔ | ✔ 6 次 | w7 端点；加密体 |
| Message | `Message/unreadMessageNumV220` | ✔ | ✔ 10 次 | 普通端点（尾盐） |
| Discover | `Discover/getUnreadMessageNumV330` | ✔ | ✔ 10 次 | 普通端点 |
| Discover | `Discover/getSchoolServiceV330` | ✔ | ✔ 9 次 | 普通端点 |
| Statuses | `Statuses/hotV300` | ✔ | ✔ 6 次 | 普通端点 |
| Run | `Run/getTimestampV278` | ✔ | ✔ 2 次 | 普通端点；**是「必须 form-decode」的判据之一** |

### 只在静态里有、日志没抓到过的（37 条）

> 这些端点在 4.2.0 上没被踩到 → **它们的 sign 规则没有任何实测证据**。
> 一旦某个版本开始调它们，先跑 `adapt-probe` 看那条路径落在「一致 / 不同」。

| 模块 | 路径 | 静态 | 日志 |
| --- | --- | --- | --- |
| Answer | `Answer/studentAnswerListV330`、`Answer/transcriptV330` | ✔ | — |
| Article | `Article/addCommentV220`、`addLaudV220`、`delCommentV220`、`delLaudV220` | ✔ | — |
| Discover | `Discover/getListV276`、`getSchoolServiceMoreV277` | ✔ | — |
| discover | `discover/getSubModuleV330` | ✔ | — |
| Game | `Game/getSharePointsV148` | ✔ | — |
| login | `login/LoginV14`、`login/RegisterV14`、`login/Login_sanV148`、`login/GetCodeV148`、`login/getCodeV148`、`login/ForgetpwdV14`、`login/bind_phoneV14` | ✔ | — |
| Login | `Login/getCodeV300` | ✔ | — |
| Message | `Message/allListV220`、`commentV220`、`laudV220`、`officialV210` | ✔ | — |
| Run | `Run/recordDetailV270`、`stopFreeRunV220`、`stopRunV278` | ✔ | — |
| Run2 | `Run2/checkUserDeviceV278` | ✔ | — |
| SchoolAdmin | `SchoolAdmin/getModuleV277` | ✔ | — |
| Signin | `Signin/getSinginListV278` | ✔ | — |
| Statuses | `Statuses/detailV220`、`postV210`、`timelineV220` | ✔ | — |
| Student | `Student/InfoV14`、`SubmitAlumniInfoV210`、`SubmitInfoV201`、`SubmitTeacherInfoV210` | ✔ | — |
| TeacherCourse | `TeacherCourse/getFitnessScoreV330` | ✔ | — |
| User | `User/UserphotoV210` | ✔ | — |

### 如果 App 版本变了，这里最可能发生什么

按可能性从高到低：

1. **后缀数字变大**（`V330` → `V340` 之类）。但**不能预测具体值** —— 见本节开头：`V###` 与服务端世代号挂钩，只能去新 dex 里读。
2. **w7/v7 名单静默失效**（这是**最危险**的一种，因为它不报错也不崩）。
   `W7`/`V7` 是**子串匹配**：`W7` 里有 `Run2/beforeRunV260`，
   新版本一旦改叫 `Run2/beforeRunV340`，`p.includes("Run2/beforeRunV260")` 就是 `false`
   → 该端点自动掉回「尾盐 + 不排 `mobileDeviceId`」的普通规则
   → sign 和服务端算的不一致 → 该端点回 `{"status":0,"info":"非法请求"}`
   → 表现是「跑步页报错 / 登录失败」，而首页还好好的。
   **`adapt-probe` 对这种情况专门有效**：它会直接报出「期望 `P/K/m/D`，实测 `S/K/-/D`」。
3. **路径整体换代**（`V###` 直接消失，换成同名新方法或换模块名）→ 服务端可能已经不下线老接口，
   App 改调新接口。此时老路径在日志里消失、新路径出现在「未判定」里。
4. **老接口被服务端下线** → 404 或 `status` 变成别的值（不是 0 也不是「非法请求」）。

---

## §3 症状 → 可能原因 → 怎么确认

> 排查顺序建议：先跑 `adapt-probe`（30 秒，直接告诉你 sign 规则对不对），
> 再按本表对号。`adapt-probe` 能直接排掉/确认第 1、2、6 行。

| 症状 | 最可能原因 | 怎么确认 |
| --- | --- | --- |
| **全站**都回 `{"status":0,"info":"非法请求"}`（登录、首页、跑步全挂） | 尾盐变了（#1）；或拼接骨架变了（#6）；极端情况是哈希从 md5 换了 | `adapt-probe` → 若报「全局规则对不上 / 所有请求连无盐都算不出来」就是这一类。取一条日志里的 `clientSign` + 明文，手工 `md5(键名升序拼串 + 盐)` 对不上 → 盐/骨架变了 |
| **单个端点**回「非法请求」，其它正常 | 该端点的排除集变了（#3/#4/#5），或它的 `V###` 变了导致 w7/v7 名单没命中 | `adapt-probe` 会直接写出该端点「期望 X / 实测 Y」，差异字母就是答案（`m`=`mobileDeviceId`、`n`=`nick_name`+`avatar_url`、`t`=`timestamp` …）。**这是探测器最强的场景** |
| 请求 **404**，或 `status` 是个从没见过的值（不是 0、不是「非法请求」） | 接口路径变了（§2 的第 1/3 种），或服务端下线了该版本的接口 | 看 `RSP.status` 和 `RSP.bodyText`。路径变了 → 日志里会同时出现「老路径消失 + 新路径出现」；拿 `unpack/urls_all.txt` 里的候选去比对 |
| **白屏 / JSON 解析异常 / 闪退**，但 `RSP` 是 200 | 服务端返回结构变了，老 App 的 Gson 解析不了 | 看 `RSP.bodyText` 是不是空/结构不对。若是加密体，先确认 `RSP.decryptTag` 有没有值（解不开说明响应 AES 也变了） |
| **只有登录失败**，其它页面正常 | v7 端点规则变了（#4/#5）：`Login/quickLoginV339` 的 `nick_name`/`avatar_url` 排除集或首盐变动 | `adapt-probe` 里看 `Login/quickLoginV339` 那一行的判定。再用 `mitm/decrypt_quicklogin.mjs` 把该请求解密，逐条规则比对 |
| **只有加密体端点失败**（`beforeRunV260`、`RefreshToken`、`getOssSts`），明文端点正常 | 请求 AES key/iv 变了（#7/#8） | `adapt-probe` 会单独报 `[AES] … **不是 4.2.0 的请求 key，AES 已变**`，或「N 个加密体用全部 4 组候选 key/iv 都解不开」。日志里这些端点的 `REQ.bodyText` 会是 `key=…` 但 `decryptTag` 为空/错组 |
| **全部正常，但还是弹「版本过低」** | `system/update` 的响应字段或 AES 变了（#9/#10/#13/#14） | 看 `REWRITE_RSP` 记录在不在。**没有** `REWRITE_RSP` → 响应根本没被改写（`rspDecrypt` 抛了 / 外层不是 `is_encrypt`+`data`）。**有** `REWRITE_RSP` 但还弹 → 客户端比较的是别的字段，看 `before`/`after` 里的键名 |
| **图片不显示 / 图片加载慢** | 拦截范围收得太宽（#16），或 CA 没被信任（#18） | `proxy.out.log` 里 `TLSERR` 暴涨 + `CONNECT` 数远超请求数 → 拦宽了（把 `data.lptiyu.com` 也 MITM 了）。若只有图片坏、API 正常 → 先确认 `INTERCEPT_RE` 是不是被临时放宽过 |
| **一个请求都抓不到**（`adapt-probe` 说 "no REQ records"） | 代理没跑 / 目标 IP 变了没刷新 / 域名变了（#16） | `tanke-proxy.sh status` + `selftest`。IP 类问题 `tanke-proxy.sh refresh` 就能修；域名类问题只能改 `INTERCEPT_RE` |
| **代理在跑、也有 `REQ`，但 `adapt-probe` 说全都「未判定」** | 请求体里没有 `sign`，或 body ≥ 20000 字节把 `bodyText` 截了 | 看报告的「未判定端点」段。旧版 `proxy.mjs` 没有 `signTail` → 先升级到 v2.3.1 再测 |

---

## §4 怎么跑探测器

```sh
# 设备上（推荐）
su -c 'sh /data/adb/tanke-proxy/tanke-proxy.sh adapt-probe'

# 或者直接跑包装脚本（两个位置都放着）
su -c 'sh /data/adb/tanke-proxy/adapt-probe.sh'
su -c 'sh /data/adb/modules/tanke_proxy/adapt-probe.sh'

# 报告在设备上
#   /data/data/com.termux/files/home/tanke-proxy/adapt-probe-report.txt
#   /sdcard/adapt-probe-report.txt          ← 这个可以直接 adb pull
adb pull /sdcard/adapt-probe-report.txt

# PC 上（把日志拉回来跑，便于 -v 看明细）
node adapt-probe.mjs capture.jsonl -v
node adapt-probe.mjs capture.jsonl --json
```

**读结果只看三行**：

```
[结论]  全部 N 个端点、M 个请求都命中 4.2.0 的规则 → 一致（退出码 0）
[结论]  a/b 个命中…；k 个端点对不上 → 不一致（退出码 2）
[下一步] 里面已经写明是「盐变了」还是「排除集变了」还是「拼串/哈希变了」
```

**规则标签怎么读**：`<盐>/<排序>/<排除集>/<编码>`

```
S = 尾盐 rDJiNB9j7vD2      P = 首盐 eFoqdHOdDy6ViJ0i      N = 无盐
K = 键名升序               I = 出现顺序（JSON 键序 / 表单顺序）
D = 拼串前 form-decode     R = 原样（wire 上的编码）
排除集字母：f=file m=mobileDeviceId n=nick_name+avatar_url t=timestamp
            c=nonce k=token u=uid s=student_num h=school_id v=version+version_name
```

4.2.0 的三种形态：普通 `S/K/f/D`、w7 `P/K/fm/D`、v7 `P/K/fmn/D`。
标签里只写「本请求里真的有这个字段」的开关 —— 因为一个不存在的字段排不排都算出同样的 md5。

**探测器的验证记录**（证明它不是「永远说一致」的摆设）：

| 输入 | 结果 | 退出码 |
| --- | --- | --- |
| 4.2.0 真实日志（130 条请求 / 18 个端点） | 一致 130/130，主规则 `S/K/-/D` | 0 |
| 同上 + 新代理的 6 条新流量（136 条） | 一致 136/136 | 0 |
| 人为把尾盐/首盐换掉 | 0/130 命中 → 诊断「全局规则对不上」 | 2 |
| 人为把 `timestamp` 加进排除集 | 0/130 命中，且**精确报出** `S/K/t/D` | 2 |
| 人为把首尾盐对调 | 0/130 命中 → 诊断「盐变了/对调了」 | 2 |
| 日志不存在 | 「没有找到日志文件」 | 3 |

---

## §5 已知限制

1. **探测器只验证 sign**。它不验证 AES 之外的任何东西；响应结构变化、接口下线、NSC 收紧都测不出来。
2. **只覆盖日志里出现过的端点**。4.2.0 上只踩到 44 个 `V###` 路径里的 7 个、外加若干无后缀路径。
   没被抓到的端点，其规则**没有实测证据**。
3. **`V###` 无法预测**。它是服务端世代号（4.2.0 的 vc=220，却调 `V260`…`V339`），只能从新 APK 的 dex 里读。
4. **`signTail` 在 4.2.0 上从不触发**（body 远小于 8000 字符），它是给「新版本 body 变大」留的保险，
   在正常流量上不会出现——所以「日志里看不到 `signTail`」是正常的，不是坏了。
5. **判别力有限**：130 条请求里只有 7 条只被唯一一条规则命中。
   其余请求因为「body 里没有需要 URL 解码的字符」或「字段本来已按名排好」，
   会让 `D≡R`、`K≡I` 同时成立——这是数据本身提供不了区分信息，不是探测器有 bug。
   真要区分 `D`/`R`，靠 `Report/appLog`（`fileName` 含 `%2F`）这类端点。
