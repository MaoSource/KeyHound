# KeyHound

从内存 dump 里捞 KEY、再对密文做并发硬解的桌面工具。基于 Rust + egui, 单文件可执行, 无需安装运行环境。

## 它做什么

给你一段密文 (HEX / Base64) 和一份进程的内存 dump, KeyHound 会:

1. 扫描 dump, 抽出所有可能是 KEY 的字节片段 (候选 KEY)
2. 把每个候选 KEY 喂给你勾选的所有算法去尝试解密 / 校验哈希
3. 用 PKCS#7 padding、JSON 结构、ASCII 可打印率、关键字等判据筛出命中
4. 在 UI 里给你看 KEY、IV、明文预览

适合做的事: CTF 取证关、本地调试 (你自己的进程) 排查加密参数、安全研究。

> ⚠️ 只对你**有授权**的目标使用。拿别人的 dump 去硬解算未经授权访问。

## 支持的算法

| 类别 | 算法 |
|------|------|
| 对称 (块) | AES-ECB/CBC/CFB/CTR/GCM, DES-ECB/CBC, 3DES-ECB/CBC, SM4-ECB/CBC/CFB |
| 对称 (流) | RC4, ChaCha20 |
| 哈希 | MD5, SHA-1, SHA-256, SHA-512, SM3, RIPEMD-160 |
| HMAC | HMAC-MD5, HMAC-SHA-1/224/256/384/512, HMAC-SHA-3, HMAC-SM3, HMAC-RIPEMD |

非对称 (RSA / SM2 / ECDSA / Ed25519) 暂未实现, 在 UI 里默认不勾选。

## 输入

- **索引文件**: `.dmp` / `.bin` / `.so` / `.dll` / `.dat` / `.raw`, 可拖放, 可多文件
- **密文**: HEX 或 Base64, 自动识别

## 构建

需要 Rust stable。

```bash
cargo build --release
./target/release/keyhound
```

macOS 上做通用二进制:

```bash
cargo build --release --target x86_64-apple-darwin
cargo build --release --target aarch64-apple-darwin
lipo -create \
  target/x86_64-apple-darwin/release/keyhound \
  target/aarch64-apple-darwin/release/keyhound \
  -output target/release/keyhound-universal
```

## 发布

打 `v*` 标签会触发 `.github/workflows/release.yml`, 自动构建 Windows x86_64 和 macOS Universal 二进制并发布到 GitHub Release:

```bash
git tag v0.1.0
git push origin v0.1.0
```

## 主要参数

- **深度搜索**: 扫描步长从 KEY 长度的一半改为 1 字节, 能命中未对齐位置的 KEY, 慢约 8 倍
- **剔除重复**: 对候选 KEY 用 64-bit 内容哈希去重, 默认开启
- **编码 KEY**: 把候选片段同时按原始字节和 HEX/Base64 解码后的字节都试一遍
- **候选长度**: 限定 KEY 字节长度, 例如 `8, 16, 24, 32`
- **已知明文**: 哈希反查 (输入 hash 的明文猜测) 或 HMAC 的 message
- **原文包含**: 解密结果里必须出现的子串, 用作命中过滤器
- **并发**: 默认线程数 = CPU 核数

## 项目结构

```
src/
  main.rs     入口, eframe 启动
  app.rs      UI: workspace 表单、文件列表、结果卡片、日志
  engine.rs   推算引擎: 候选提取 + 并发尝试 + 命中判据
  data.rs     算法清单 / 默认勾选 / 示例规则
  theme.rs    egui 样式 token
```
