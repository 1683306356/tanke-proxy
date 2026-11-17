# 叶证书配置 / leaf certificate configuration

发布包**不包含**证书。以下描述的是部署时在设备上由 `gencert.mjs` 生成的叶证书配置，
只描述通用配置（域名、SAN、有效期和签发关系），不记录任何设备的证书指纹、精确签发时间或私钥。

## 为什么是预生成而不是运行时签发

`proxy.mjs` 只对三个固定域名做 TLS 终止（`INTERCEPT_RE`，硬编码，可被环境变量覆盖但默认不变）：

```
/^(api2|api|pre-api)\.lptiyu\.com$/i
```

v2 用 `node-forge` 在运行时按 SNI 动态签叶证书，每次都要一次 RSA-2048 keygen，并依赖
`node_modules/node-forge`。域名集合是固定的、极小的，动态签发没有收益，却带来两个成本：
node_modules 依赖、以及每次新 SNI 的延迟。

v3 改为：部署时一次性生成 3 张叶证书，`proxy.mjs` 启动时读取成表，握手时按 SNI 查表。
证书表为空或某个域名缺失时，该域名**不拦截**（原样透传）并记 `LEAF_MISS`，
`tanke-proxy.sh selftest` 会判 FAIL —— 不会静默降级。

## 生成方式

```
node gencert.mjs ca  -d <dir>                      # 根 CA（仅缺失时生成，已存在则沿用）
node gencert.mjs leaf -d <dir> --host <域名>        # 单张叶证书
node gencert.mjs ensure -d <dir> --hosts a,b,c     # 缺什么补什么，绝不覆盖已有
node gencert.mjs verify -d <dir> --hosts a,b,c     # 验链 + 验域名 + 真 TLS 握手
```

`gencert.mjs` 只用 `node:crypto`：RSA-2048 由 `generateKeyPairSync` 产生，X.509 v3 的 DER
由脚本内的 ASN.1 writer 构造，签名用 `crypto.createSign('RSA-SHA256')`。
Android 上没有 `openssl` 二进制，所以没有走 shell 调用外部工具这条路。

## 结构

| 项 | 值 |
| --- | --- |
| 根 CA subject | `CN=LPTIYU Lab Root CA, O=Lab, C=CN` |
| 根 CA 有效期 | 3650 天（生成时 now-1d ~ now+3650d） |
| 根 CA 扩展 | `basicConstraints` (cA:true, critical) / `keyUsage` (keyCertSign+cRLSign, critical) / `subjectKeyIdentifier` |
| 叶证书 subject | `CN=<域名>` |
| 叶证书 SAN | `DNS:<域名>`（单域名，不含通配符） |
| 叶证书有效期 | 1825 天 |
| 叶证书扩展 | `basicConstraints` (cA:false, critical) / `keyUsage` (digitalSignature+keyEncipherment, critical) / `extKeyUsage` (serverAuth) / `subjectAltName` / `subjectKeyIdentifier` / `authorityKeyIdentifier` |
| 签名算法 | sha256WithRSAEncryption (1.2.840.113549.1.1.11) |
| 密钥长度 | RSA 2048 |
| 私钥格式/权限 | PKCS#8 PEM，`0600`，仅 root |

`issuer` 不是从字符串重建的：`gencert.mjs` 直接取**现有 CA 证书 TBS 里 subject 字段的原始 DER 字节**
作为叶证书的 issuer，因此即使 CA 是旧版 node-forge 生成的，也能字节级对齐。

## 设备上生成的证书

每台设备部署时独立生成 CA 及三张叶证书。证书文件和私钥不得打入发布包。
具体指纹、序列号及签发时刻只在本机核对，本文不保留任何真机样本。

| 域名 | 证书文件 |
| --- | --- |
| `api2.lptiyu.com` | `leafs/api2.lptiyu.com.crt.pem` |
| `api.lptiyu.com` | `leafs/api.lptiyu.com.crt.pem` |
| `pre-api.lptiyu.com` | `leafs/pre-api.lptiyu.com.crt.pem` |

## 验证方式

在设备上按上文运行 `gencert verify`，结果仅在本机查看。
`verify` 做四件事，缺一不算通过：

1. `X509Certificate` 解析 CA，确认 `ca=true` 且未过期；
2. 对每张叶证书检查 `checkIssued(CA)`、`verify(CA.publicKey)`（签名真的由 CA 私钥产生）、`checkHost(域名)`、有效期；
3. 私钥 ↔ 证书配对（签名/验签往返）；
4. 在 127.0.0.1 起一个真实 TLS 服务端，用 `ca` 作为唯一信任锚做**默认校验**的客户端握手，`servername` = 目标域名 —— 等价于设备侧的证书校验。
