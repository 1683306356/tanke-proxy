# CHANGELOG

## v3.0.1

修 `common.sh` 里 `log()` 用全局变量 `n` 统计日志行数、与 `apply_iptables()` 的规则计数器撞名，导致 `state.env` 的 `rules=` 写成日志行数（应为 2）。纯报表缺陷，运行时行为与 v3.0.0 一致。

## v3.0.0

自包含发布：内置 node 运行时（`bin/node` + 10 个 `.so`，RUNPATH 改写到模块目录）、去掉 node-forge 改用纯 `node:crypto` 手写 DER 的 `gencert.mjs`、证书首次部署在手机上生成、`selftest` 扩到 13 项、新增 `deps` 依赖自检。

## v2.3.1-adaptprobe

新增 `adapt-probe.sh` / `adapt-probe.mjs`，一条命令判断「手机上这个乐跑版本是否还套用同一套 sign 规则」，退出码 0/2/3 分别表示一致 / 不一致 / 数据不足。

## v2.3-robust

稳健性一轮：看门狗 300s → 25s 并改用「端口 + 心跳」双判据；`proxy_pids` 从每 PID fork `tr` 改成一次扫描（restart 67s → ~12s）；uid 漂移自愈；日志轮转（`capture.jsonl` 8 MiB、`proxy.out.log` copytruncate 4 MiB、`boot.log` 4000 行）；反向保护——连续 6 次起不来就撤掉 iptables 跳转让 App 直连。

## v2.1-signformdecode

明文表单先 `form-decode` 再算签名，修「非法请求」；此前对 URL 编码后的原串签名，服务端校验不过。

## v2.1-fix

v7 端点排除 `nick_name` / `avatar_url` 字段，修登录失败。

## v2.1

加响应侧改写 `system/update`，把「有新版本」改成「已是最新」，版本更新弹窗消失。

## v2

改成 iptables per-app `REDIRECT` + 透明模式（不再有 `CONNECT` 那一层，避免丢 ClientHello）；系统级 `http_proxy` 永不设置。

## v1

全局 `http_proxy=127.0.0.1:8888` + 单域名拦截。问题是全机流量都进代理：`data.lptiyu.com` 被卷进 30,718 次重连，单线程 node 顶不住，**其他 App 全部表现为断网**。
