# ACME PoP 申请场景

以下命令统一使用域名 `client.minihook.xyz` 和 `dns_ali` 完成 DNS 验证。

```sh
export Ali_Key='你的阿里云 AccessKey'
export Ali_Secret='你的阿里云 AccessSecret'

ACME_SERVER='https://acme.mtc-test.trustasia.com/acme/v2/directory'
CERT_PROFILE='mtc-7d'
DOMAIN='client.minihook.xyz'
```

| 场景 | 公钥来源 | PoP proof 来源 | 参考命令 | 说明 |
| --- | --- | --- | --- | --- |
| 自动生成 ECDSA 私钥 | acme.sh 自动生成 | 本地私钥 | `./acme.sh --issue --acme-pop --server "$ACME_SERVER" --cert-profile "$CERT_PROFILE" --dns dns_ali --dnssleep 30 -d "$DOMAIN" --keylength ec-256` | 默认推荐方式；私钥保存在 acme.sh 证书目录。 |
| 自动生成 ML-KEM 私钥 | acme.sh 自动生成 | 本地 ML-KEM 私钥 | `./acme.sh --issue --acme-pop --server "$ACME_SERVER" --cert-profile "$CERT_PROFILE" --dns dns_ali --dnssleep 30 -d "$DOMAIN" --keylength ml-kem-768` | 需要 OpenSSL 3.5+；ML-KEM 不能回退 CSR。 |
| 已有本地私钥 | 从私钥导出 | `--pop-private-key` 指定的私钥 | `./acme.sh --issue --acme-pop --server "$ACME_SERVER" --cert-profile "$CERT_PROFILE" --dns dns_ali --dnssleep 30 -d "$DOMAIN" --pop-private-key /secure/keys/client.key` | 不生成新私钥，不提交 CSR。 |
| CSR + 本地私钥 | 从 CSR 提取域名和公钥 | CSR 对应的本地私钥 | `./acme.sh --issue --acme-pop --server "$ACME_SERVER" --cert-profile "$CERT_PROFILE" --dns dns_ali --dnssleep 30 --csr /secure/keys/client.csr --pop-private-key /secure/keys/client.key` | CSR 只作为域名和公钥输入，finalize 仍发送 `{}`。 |
| 公钥文件 + 本地私钥 | `--pop-public-key` | `--pop-private-key` | `./acme.sh --issue --acme-pop --server "$ACME_SERVER" --cert-profile "$CERT_PROFILE" --dns dns_ali --dnssleep 30 -d "$DOMAIN" --pop-public-key /secure/keys/client-public.pem --pop-private-key /secure/keys/client-private.pem` | acme.sh 会检查公钥和私钥是否匹配。 |
| 公钥文件 + 外部 proof 程序 | `--pop-public-key` | `--pop-proof-command` | `./acme.sh --issue --acme-pop --server "$ACME_SERVER" --cert-profile "$CERT_PROFILE" --dns dns_ali --dnssleep 30 -d "$DOMAIN" --pop-public-key /secure/keys/client-public.pem --pop-proof-command /usr/local/bin/client-pop-proof` | 外部程序输出最终 base64url proof；该参数只接受可执行文件路径或命令名。 |
| provider + key reference | provider 返回公钥 | provider `sign` 或 `decap` | `./acme.sh --issue --acme-pop --server "$ACME_SERVER" --cert-profile "$CERT_PROFILE" --dns dns_ali --dnssleep 30 -d "$DOMAIN" --pop-provider pop_command --pop-key-ref device-42` | 适合 HSM、KMS、Token 或签名服务。 |
| CSR + provider | 从 CSR 提取域名和公钥 | provider `sign` 或 `decap` | `./acme.sh --issue --acme-pop --server "$ACME_SERVER" --cert-profile "$CERT_PROFILE" --dns dns_ali --dnssleep 30 --csr /secure/keys/client.csr --pop-provider pop_command --pop-key-ref device-42` | provider 返回的公钥必须与 CSR 公钥一致。 |
| 公钥文件 + provider | `--pop-public-key` | provider `sign` 或 `decap` | `./acme.sh --issue --acme-pop --server "$ACME_SERVER" --cert-profile "$CERT_PROFILE" --dns dns_ali --dnssleep 30 -d "$DOMAIN" --pop-public-key /secure/keys/client-public.pem --pop-provider pop_command --pop-key-ref device-42` | provider 返回的公钥必须与指定公钥一致。 |
| 交互式人工 proof | 交互输入公钥路径 | 交互输入 proof | `./acme.sh --issue --acme-pop --server "$ACME_SERVER" --cert-profile "$CERT_PROFILE" --dns dns_ali --dnssleep 30 -d "$DOMAIN" --pop-manual` | 需要交互终端；会提示输入公钥路径和 proof。 |
| CSR + 交互式 proof | 从 CSR 提取公钥 | 交互输入 proof | `./acme.sh --issue --acme-pop --server "$ACME_SERVER" --cert-profile "$CERT_PROFILE" --dns dns_ali --dnssleep 30 --csr /secure/keys/client.csr --pop-manual` | 公钥来自 CSR，只提示输入 proof。 |
| `--sign-csr` 兼容模式 | 从 CSR 提取公钥 | 本地私钥、provider 或其他 proof 来源 | `./acme.sh --sign-csr --acme-pop --server "$ACME_SERVER" --cert-profile "$CERT_PROFILE" --dns dns_ali --dnssleep 30 --csr /secure/keys/client.csr --pop-private-key /secure/keys/client.key` | 兼容传统 acme.sh CSR 命令；新流程建议使用 `--issue --csr`。 |

## `pop_command` 配置

使用 `--pop-provider pop_command` 时，需要配置对应的操作程序：

```sh
export POP_CommandPublicKey=/usr/local/bin/pop-get-public-key
export POP_CommandSign=/usr/local/bin/pop-sign
export POP_CommandDecap=/usr/local/bin/pop-decap
```

`POP_CommandPublicKey` 根据 key reference 输出 base64url DER SPKI 公钥。签名程序通过以下环境变量接收输入：

```text
POP_KEY_REF
POP_ALGORITHM
POP_MESSAGE
```

KEM 解封装程序通过以下环境变量接收输入：

```text
POP_KEY_REF
POP_ALGORITHM
POP_CIPHERTEXT
```

provider 模式下，acme.sh 负责 PoP message、HKDF、HMAC 和 newOrder 绑定；provider 只负责公钥读取、签名或 KEM 解封装。

## 参数约束

- `--csr` 和 `--pop-public-key` 不能同时使用。
- `--pop-provider` 必须同时提供 `--pop-key-ref`。
- `--pop-key-ref` 必须同时提供 `--pop-provider`。
- provider 不能和 `--pop-private-key`、`--pop-proof-command`、`--pop-manual` 同时使用。
- `--pop-proof-command` 只接受可执行文件路径或命令名，不解析命令参数。
- `--key-file` 是签发后复制证书私钥的输出路径，不是 PoP 私钥输入参数。
- DNS 验证由 `dns_ali` 完成，PoP 只证明证书公钥对应的私钥控制权。

## 续期

本地私钥、provider 和外部 proof 配置会保存到域名配置中。非交互模式可以使用：

```sh
./acme.sh --renew -d "$DOMAIN" --force --ecc
```

`--pop-manual` 的续期仍需要交互输入 proof，不适合直接由无人值守 cron 完成。
