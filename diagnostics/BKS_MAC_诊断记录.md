# BKS v1 / v2 MAC 密钥派生差异诊断记录

- 日期：2026-11-13
- 对象：PyJKS（本地基线 `8312b46`，上游 `0a046e5`），模块 `jks/bks.py`
- 材料：仅使用仓库自带公开测试库 `tests/keystores/bks/` 与公开测试口令（`""`、`"12345678"`、`"store_password"`）
- 约束：不接触真实用户口令；全程离线；无在线猜测
- 复现：`.venv/bin/python diagnostics/bks_mac_audit.py`（输出存档 `diagnostics/audit_output.txt`）
- 基线测试：`69 passed`

## 1. 结论摘要

团队把一批历史 BKS 文件标成“相同级别的完整性证据”这一做法不成立。BKS v1 与 v2 虽然走同一段校验代码、HMAC 算法都是 HMAC-SHA1、尾部都存 20 字节摘要，但**派生出来的 MAC 密钥长度相差 8 倍**：v1 只有 2 字节（16 bit），v2 是完整 20 字节（160 bit）。v1 的完整性只相当于对一个 16 位空间的承诺，可在离线状态下穷举，不能与 v2 等量齐观。

## 2. 从版本字段到加载结果的完整追踪

### 2.1 版本字段

`jks/bks.py:271-273`：读取文件头前 4 字节大端无符号整数作为 `version`，仅接受 `1` 或 `2`，否则抛 `UnsupportedKeystoreVersionException`。版本号本身不参与 HMAC 计算，只决定派生密钥长度这一个分支。

文件布局（以 `empty.bksv1` 实测，共 53 字节）：

```
version(4) | salt_len(4) | salt(20) | iteration_count(4) | entry_region... | HMAC-SHA1(20)
00000001     00000014      e3ce..      00000472             00(终止符)         a078..
```

### 2.2 派生长度（关键差异点）

`jks/bks.py:281-284`：

```python
hmac_fn = hashlib.sha1
hmac_digest_size = hmac_fn().digest_size            # 20 字节
hmac_key_size = hmac_digest_size*8 if version != 1 else hmac_digest_size
hmac_key = rfc7292.derive_key(..., hmac_key_size//8)
```

- v2 分支：`hmac_key_size = 20*8 = 160`（单位是 bit），`//8 = 20` 字节 → 请求 20 字节密钥。
- v1 分支：`hmac_key_size = 20`，这里 20 被当作 bit 数传入，`//8 = 2` 字节 → **只请求 2 字节密钥**。

`rfc7292.derive_key`（`jks/rfc7292.py:21-67`）的末参 `desired_key_size` 语义是“字节数”，内部 `c = ceil(desired_key_size / 20)` 决定迭代轮数，最后 `derived_key[:desired_key_size]` 截断。因此 v1 只产生 1 轮 SHA-1 输出再截断到 2 字节；v2 产生完整 1 轮 20 字节。该分支是 PyJKS 针对 v1 写入端实际产物的兼容行为：对全部三个 v1 测试库，用 2 字节密钥独立重算 HMAC 均与文件尾部逐字节匹配（见 2.2 表与第 4 节），说明 v1 文件确实是以 2 字节 MAC 密钥生成的，PyJKS 是在如实读取一个本身就弱的格式，而非本地实现笔误。是否源自 BouncyCastle 历史版本的 bit/byte 传参问题，属于上游背景，本地材料不做断言。

独立复算（标准库 `hmac`/`hashlib` 自行实现 RFC 7292 附录 B，不调用 pyjks）与 pyjks 的 `derive_key` 输出逐字节相等：

| 文件 | 版本 | 实际派生密钥字节数 | 派生密钥（hex） | 与 pyjks 一致 |
|---|---|---|---|---|
| empty.bksv1 | 1 | **2** | `41e9` | 是 |
| christmas.bksv1 | 1 | **2** | `dd9f` | 是 |
| custom_entry_passwords.bksv1 | 1 | **2** | `dff2` | 是 |
| empty.bksv2 | 2 | **20** | `81d453…f4e8` | 是 |
| christmas.bksv2 | 2 | **20** | `d2b134…2c07` | 是 |
| custom_entry_passwords.bksv2 | 2 | **20** | `3ddf6e…f15a9` | 是 |

### 2.3 HMAC 覆盖范围

`jks/bks.py:279,286-296`：`store_data = data[pos:pos+size]`，其中 `pos` 紧跟在 `version+salt+iter` 头部之后，`size` 是条目解析返回的偏移（含末尾 1 字节 `0x00` 终止符）。HMAC 只覆盖**条目区**，不覆盖 32 字节文件头（版本、salt、迭代计数），也不覆盖自身尾部 20 字节。

实测（christmas.bksv2，2070 字节）：覆盖字节 32..2049（2018 字节），头部 0..31 与尾部 2050..2069 均不在覆盖范围内。

篡改 salt 中 1 个字节、保持尾部 HMAC 不变的实验证明：
- 用**原**派生密钥对未变的条目区重算，HMAC 仍然匹配 —— 头部确实在覆盖范围之外；
- 真实解析器会用**被改后的 salt** 重新派生密钥，得到新密钥后 HMAC 不匹配 —— 头部篡改只能通过“KDF 输入变了”被间接发现，而不是被 HMAC 直接保护。

### 2.4 加载结果与门控顺序

`loads()` 的顺序是：解析版本 → 读 salt/iter → `_load_bks_entries` 先把全部条目结构化解析出来（`jks/bks.py:279`）→ 然后才派生密钥并校验 HMAC（281-296）→ 失败抛 `KeystoreSignatureException`，成功才返回 `BksKeyStore`。

含义：
- “格式可读”不需要正确口令，条目元数据（别名、类型、证书、时间戳）在 MAC 门控之前就已解析。实测 MAC 损坏的 christmas 库，仍可解析出 6 个条目。
- 密封条目（sealed）的解密是另一条独立链路（PKCS#12 PBE + 3DES，`jks/bks.py:191-196`），与仓库级 MAC 不共享密钥；默认 `try_decrypt_keys=True` 时解密失败会被静默跳过（`jks/bks.py:335-339`），不影响仓库 MAC 通过。即“仓库口令校验通过”不等于“每个条目都能解开”。

## 3. 异常场景记录（均在本地公开材料上实测）

| 场景 | 操作 | 实测结果 |
|---|---|---|
| 版本字段改写为受支持值 | christmas.bksv1 的 `1→2`、christmas.bksv2 的 `2→1`，口令保持正确 | `KeystoreSignatureException: Hash mismatch`。版本切换改变派生长度（2↔20 字节），密钥不再匹配；不会加载成功 |
| 版本字段改写为不支持值 | 同样两文件改成 `3` | `UnsupportedKeystoreVersionException`，在任何加密计算之前拒绝 |
| 空仓库 | `empty.bksv1` / `empty.bksv2`，口令 `""` | 条目区仅 1 字节 `0x00` 终止符；两者均 `loads()` 成功，`entries=0`，`version` 分别为 1/2。空仓库同样带 HMAC，且 v1 空仓库的 MAC 仍是 2 字节密钥 |
| 正确口令 + MAC 错误 | 四个库尾部 HMAC 翻转 1 bit，口令保持正确 | 一律 `KeystoreSignatureException`；但条目在抛错前已可结构化解析（christmas 6 条、empty 0 条） |
| 错误口令（补充对照） | christmas v1/v2 用错误公开测试口令 | 均 `KeystoreSignatureException`，与“MAC 被篡改”是同一异常、同一消息，调用方无法据异常类型区分口令错与内容被改 |

## 4. v1 弱密钥空间的独立验证

对 `empty.bksv1`，不使用口令，直接在 0..65535 的 2 字节密钥空间内逐个计算 HMAC-SHA1：

- 尝试次数：65536；
- 无口令恢复出的密钥：`41e9`；
- 用正确口令经 RFC 7292 派生的密钥：`41e9`（长度 2）；
- 两者完全相同。

对 `empty.bksv2` 做同样 65536 次 2 字节尝试：无任何命中（v2 密钥是 20 字节、160 bit 空间）。

结论：v1 的仓库完整性可被任何能读取该文件的人离线伪造（重算条目区的 HMAC 并替换尾部），成本是至多 65536 次 HMAC-SHA1，毫秒级。它能挡住意外损坏和弱脚本误改，但挡不住有意篡改，不具备抗敌手的完整性保证。HMAC-SHA1 的抗碰撞强度在此不是瓶颈，瓶颈是 16 bit 密钥。

## 5. 对“同级别完整性证据”结论的影响

- v1 与 v2 的“校验通过”是同名不同质：通过只证明“某条 HMAC 与当前派生密钥+条目区一致”，而 v1 该密钥仅 16 bit。
- 头部（版本、salt、迭代计数）不在 HMAC 覆盖内；版本号还能被改写以切换派生分支。完整性声称的范围仅限条目区字节。
- 校验通过不区分“正确口令”与“未被篡改”两种语义，异常类型也不区分口令错误与篡改。
- 因此历史 v1 文件即使全部校验通过，也只能证明格式自洽与口令匹配，不能提升到 v2 的完整性保证等级，更不能当作满足现代安全策略的证据。

## 6. 建议的导入分级规则（三级，不把删除兼容作为唯一方案）

### L0 — 格式可读（structural / parseable）
- 判定：版本字段 ∈ {1,2}，头部与条目区可被 `_load_bks_entries` 无异常解析。
- 不要求：正确口令、MAC 通过。
- 可用于：清点别名、条目类型、证书、时间戳等元数据；导入管道的预检与隔离队列。
- 禁止：据此信任任何密钥材料或声明完整性。

### L1 — 口令对应的校验通过（password-bound MAC verified）
- 判定：L0 且 `loads()` 未抛 `KeystoreSignatureException`，并按版本分别记录：
  - **L1-v2（强）**：20 字节 HMAC 密钥、HMAC-SHA1 覆盖条目区；可作为条目区未被篡改、且持有正确仓库口令的证据。
  - **L1-v1（弱）**：2 字节 HMAC 密钥（16 bit，已验证可离线穷举伪造）；仅证明与口令一致和格式自洽，**不**证明抗敌手完整性。应打“legacy/weak-MAC”标签，限制用途、触发告警，并要求迁移。
- 附加检查：密封条目是否实际解密成功需单独确认（仓库 MAC 通过不代表条目可解开）；记录 `try_decrypt_keys` 的结果而不是假设成功。
- 空仓库：可到 L1，但没有条目可供完整性背书，仅证明容器本身自洽。

### L2 — 满足新安全策略（policy-compliant）
- 必要条件（全部满足）：
  1. 版本为 v2（v1 一律不得进入 L2，无论 MAC 是否通过）；
  2. L1-v2 校验通过，且头部字段（版本、salt、迭代计数）在带外登记/复核，弥补头部不在 HMAC 覆盖内的缺口；
  3. 迭代计数达到策略下限，salt 长度与随机性复核；
  4. 条目级保护（sealed PBE）与密钥口令策略复核通过；
  5. SHA-1 相关策略：若策略已禁用 SHA-1 系原语，需先迁移到现代格式（如 PKCS#12 with PBKDF2/SHA-256 或 BC 的 BCFKS），不得仅凭 v2 入 L2。
- v1 迁移路径：用已知正确口令导入（L1-v1）→ 在受控环境重新封装为 v2 或 BCFKS/PKCS#12 → 新容器重新走 L2 评定；迁移前保留隔离与审计留痕。

### 工程落地建议（保留读取兼容）
- 保留 PyJKS 对 v1 的读取能力以便取证和迁移，但在 `loads()` 成功返回后由调用方按 `store.version` 强制分级，禁止把 v1 与 v2 写入同一信任桶。
- 导入管道区分捕获 `UnsupportedKeystoreVersionException`（版本问题）、`BadKeystoreFormatException`（结构问题）、`KeystoreSignatureException`（口令/篡改二义，需结合带外信息研判）。
- 对 v1 文件自动附加弱 MAC 风险标记与迁移工单；对版本字段与文件声明来源不一致的文件直接隔离。
- 不建议通过删除 v1 支持来“解决”问题：这会丢失对历史库的取证/迁移能力，且无法回应已经在库中的存量文件；分级+迁移才是可运营的方案。

## 7. 复现与文件清单

- 脚本：`diagnostics/bks_mac_audit.py`（纯标准库独立 KDF + 调用 pyjks 双路验证）
- 原始输出：`diagnostics/audit_output.txt`
- 涉及源码：`jks/bks.py:271-296`（版本、派生、HMAC、门控）、`jks/bks.py:302-345`（条目先解析）、`jks/rfc7292.py:21-67`（KDF 截断语义）
