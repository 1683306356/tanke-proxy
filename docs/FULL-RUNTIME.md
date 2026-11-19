# full 内置运行时与本次复核

v3.0.1 的 full 与 lite 使用相同的模块脚本；full 另附 arm64 / AArch64 的 Node.js 及十个动态库。full 无需另装 Termux。已发布的 lite 安装包保持原校验值。

模块运行代码来自 v3.0.1 标签（提交 `5407f70c9db1701339d209c204b45760645a584f`）。本次只补充 full 运行时、完整上游许可，并更新包内发布说明及仓库文档；未改动代理功能或已确认的完整日志行为。

## 组件与来源

| 组件 | Termux 包版本 | 随包许可文件 |
| --- | --- | --- |
| Node.js | 26.13.1 | node-LICENSE.txt，含 SWC / Amaro 等内嵌依赖声明 |
| c-ares | 1.34.9 | c-ares-LICENSE.txt |
| libffi | 3.8.0 | libffi-LICENSE.txt |
| zlib | 1.4 | zlib-LICENSE.txt |
| OpenSSL | 1:3.6.5 | openssl-LICENSE.txt、AUTHORS、README 版权声明 |
| ICU | 79.1 | icu-LICENSE.txt，含 Unicode License V3 及第三方声明 |
| SQLite | 3.54.1-1 | sqlite-LICENSE.md |
| libc++ | 30 | llvm-libcxx、libcxxabi、libunwind 的 LICENSE 文本 |

运行时及完整许可只在 full ZIP 内提供，路径为 `third_party/runtime/`。模块自定义 LICENSE 仅约束作者有权许可的内容，各第三方组件保留其原有条款。

版本来自本次所提供的 Termux `.deb` 元数据。libc++ 的包版本 30 并不代表 LLVM 主版本 30；该文件的编译元数据指向 Android LLVM 提交 `9f872551d3c681d06fd303b36f16ed5c274735eb`，对应许可从该提交取得。

七个 `.deb` 从 Termux 官方包池重新下载后与本地文件的 SHA-256 一致；libffi 3.8.0 的原包 URL 已返回 404，本次仅核对了本地原包及所提供的 Packages 索引，未独立验证该索引签名。完整包哈希及许可文本来源记录随 full 包提供，不将此文件核对等同于完整供应链认证。

## 二进制修改与依赖

11 个文件均已与 `.deb` 中的原文件逐一对照：十个文件只修改 ELF 的 DT_RUNPATH 字符串，从 `/data/data/com.termux/files/usr/lib` 改为 `/data/adb/modules/tanke_proxy/lib`，保留文件长度；`libc++_shared.so` 不变。差异符合仓库中的 `tools/patch-runpath2.mjs`。

静态 DT_NEEDED 依赖由包内十个动态库和 Android 系统的 `libc.so`、`libm.so`、`libdl.so` 满足。此检查不覆盖 Android 版本、SELinux、证书信任或设备运行行为；本次未进行新的真机测试，原文档的历史测试记录仍只代表原记录。

## 发布文件与敏感信息复核

full 按明确文件列表重新组装，未直接发布旧 full ZIP。模块脚本及 LICENSE 与已审查的 lite 对照，另更新说明文档和第三方声明；包内不加入设备证书、私钥、抓包、账号样本或运行日志。ZIP 路径、条目、CRC、记录的权限位及 SHA-256 另行核对。当前 Windows 构建的 ZIP 创建平台标记为 FAT，不能保证任意解压工具恢复 Unix 权限；Magisk 安装的 `customize.sh` 与手工部署的 `deploy.sh` 会执行 chmod，实际设备安装仍需自检。

模式扫描的命中保留人工判断：上游许可证中的邮箱、版权人和链接属于原有公开声明；Node.js 内八处类似访问密钥的字节模式位于同一份 Base64 编码的 SWC WebAssembly 资源中，已对照原 `.deb` 并严格解码核对，不能据此删除或篡改该资源。没有为消除命中而放宽扫描规则。

安装后新生成的 `capture.jsonl` 等日志仍可能含登录态及个人信息，分享前需另行清洗。

## 内置文件校验值

```text
a31e39faf7e49028354d708e0b88698297b9337dfab03b6ce0269c0b92d199be  bin/node
05bef9d3901910c3ff8ab450b03bc8b28383d363a2290f2f7b9aed7331ea6ff7  lib/libc++_shared.so
9792756fcb3166bb4564f832dee239193cb7a7a2bb7ac2b2e7f4d230d1c8edbf  lib/libcares.so
38c3aadc61eee27d13607828b0760c5265d888ee5f1c430bd250e7426801d25c  lib/libcrypto.so.3
8ac987fde934ceca609e8238f86a7232cea624fa022db51665a65536f9b501be  lib/libffi.so
12319423cc8501a4fabe0ea151e929ec9712bad6196f3c24ad6f7dc9c6f3ee88  lib/libicudata.so.79
8d0e75a3828a0254e8d9cd827b80f6defeea25699c5d11d3cffe5a7daaa616fb  lib/libicui18n.so.79
816d1f5a2de4dc119ca8f626f5c4215729089d0625fb6b9cf8901c0fa26e850e  lib/libicuuc.so.79
6a9e43aa35eaf9f3e54604d90dc63b7b6b504c644aaac64c4b632afa852ad1b1  lib/libsqlite3.so
541ebd79e10ef4ade39efa865410eebdc829bae69a959e82e47fd0b76e521e3f  lib/libssl.so.3
120442b22dc18318069a093f6d8a63a40835ed96afb2b6e5500123ab99d73d2b  lib/libz.so.1
```
