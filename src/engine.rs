// 推算引擎: 候选 KEY 提取 + 多算法并发尝试 + 命中判据 + 后台线程驱动
//
// 设计要点:
//  * 一个 spawn 调用启动一个 OS 工作线程, 内部用 rayon 并发跑 (algo × key)
//  * 通过 mpsc::Receiver<EngineMsg> 把日志/进度/命中/完成事件喂回 UI
//  * 通过 Arc<AtomicBool> stop 让 UI 端按"停止"按钮中断
//  * IV 约定: CBC 系同时试两种 —— ① 前置 IV (密文前一块) ② 无前置 IV/零 IV
//    (整段都是密文, 真 IV 不在密文里; CBC 下 IV 只影响首块, 故首块外明文照样正确,
//    判据跳过首块即可命中)。CFB/CTR/GCM/ChaCha20 用密文头部前若干字节, ECB 无 IV
//  * 命中判据按强度从高到低: 关键字 → 完整 JSON → JSON 尾部(首块未知) → ASCII 可打印率
//    PKCS#7 解填充失败已经在 try_decrypt 内部隐式过滤掉了大部分错误 key。结构判据用
//    「文本占比」(含合法 UTF-8 多字节), 中日韩明文不会被 ASCII 阈值误杀

use std::collections::{HashMap, HashSet};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use cipher::{
    block_padding::Pkcs7, AsyncStreamCipher, BlockDecryptMut, KeyInit, KeyIvInit, StreamCipher,
};
use digest::Digest;
use rayon::prelude::*;

/// 候选 KEY 总数的硬上限, 防止超大 dump 内存爆掉
const MAX_CANDIDATES: usize = 5_000_000;
/// 字符串扫描产出的最大数量 (仅用于非流式路径)
const MAX_STRINGS: usize = 20_000_000;
/// 字符串扫描的长度下限 (字节)
const STRING_MIN_LEN: usize = 4;
/// 哈希反查的最大候选长度上限。哈希明文可以是整段 HTTP 请求体 / 长 JSON,
/// 设上限会把"超长但确实是被哈希的整体"漏掉, 因此不设上限。
const HASH_REVERSE_MAX_LEN: usize = usize::MAX;

// ─── 块密码模式 type alias ─────────────────────────────────────────

type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
type Aes192CbcDec = cbc::Decryptor<aes::Aes192>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

type Aes128EcbDec = ecb::Decryptor<aes::Aes128>;
type Aes192EcbDec = ecb::Decryptor<aes::Aes192>;
type Aes256EcbDec = ecb::Decryptor<aes::Aes256>;

type Aes128CfbDec = cfb_mode::Decryptor<aes::Aes128>;
type Aes192CfbDec = cfb_mode::Decryptor<aes::Aes192>;
type Aes256CfbDec = cfb_mode::Decryptor<aes::Aes256>;

type Aes128CtrCipher = ctr::Ctr128BE<aes::Aes128>;
type Aes192CtrCipher = ctr::Ctr128BE<aes::Aes192>;
type Aes256CtrCipher = ctr::Ctr128BE<aes::Aes256>;

type DesEcbDec = ecb::Decryptor<des::Des>;
type DesCbcDec = cbc::Decryptor<des::Des>;
type TdesEcbDec = ecb::Decryptor<des::TdesEde3>;
type TdesCbcDec = cbc::Decryptor<des::TdesEde3>;

type Sm4EcbDec = ecb::Decryptor<sm4::Sm4>;
type Sm4CbcDec = cbc::Decryptor<sm4::Sm4>;
type Sm4CfbDec = cfb_mode::Decryptor<sm4::Sm4>;

// ─── 算法注册表 ────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AlgoKind {
    AesEcb,
    AesCbc,
    AesCfb,
    AesCtr,
    AesGcm,
    DesEcb,
    DesCbc,
    TdesEcb,
    TdesCbc,
    Sm4Ecb,
    Sm4Cbc,
    Sm4Cfb,
    Rc4,
    ChaCha20,
    Md5,
    Sha1,
    Sha256,
    Sha512,
    Sm3,
    Ripemd160,
    HmacMd5,
    HmacSha1,
    HmacSha224,
    HmacSha256,
    HmacSha384,
    HmacSha512,
    HmacSha3,
    HmacSm3,
    HmacRipemd,
}

/// 按密文长度判断算法是否兼容。不兼容的算法整组跳过, 避免每个候选 key 都要进
/// try_decrypt 再被 None 拒绝。这能直接砍掉一批不可能的算法。
pub fn is_ct_compatible(kind: AlgoKind, ct_len: usize) -> bool {
    use AlgoKind::*;
    match kind {
        // 块密码 + PKCS#7: ct 必须是块大小的整数倍
        AesEcb | Sm4Ecb => ct_len > 0 && ct_len % 16 == 0,
        AesCbc | Sm4Cbc => ct_len >= 32 && (ct_len - 16) % 16 == 0,
        DesEcb | TdesEcb => ct_len > 0 && ct_len % 8 == 0,
        DesCbc | TdesCbc => ct_len >= 16 && (ct_len - 8) % 8 == 0,
        // 流模式 (CFB/CTR/GCM/ChaCha20): 只需够 IV/nonce
        AesCfb | AesCtr | Sm4Cfb => ct_len >= 16,
        AesGcm => ct_len >= 12 + 16,
        ChaCha20 => ct_len >= 12,
        // 流密码 RC4 任意长度
        Rc4 => ct_len > 0,
        // 哈希 / HMAC: 兼容性由 try_hash/try_hmac 内部决定
        _ => true,
    }
}

impl AlgoKind {
    pub fn is_hash(self) -> bool {
        matches!(
            self,
            AlgoKind::Md5
                | AlgoKind::Sha1
                | AlgoKind::Sha256
                | AlgoKind::Sha512
                | AlgoKind::Sm3
                | AlgoKind::Ripemd160
        )
    }
    pub fn is_hmac(self) -> bool {
        matches!(
            self,
            AlgoKind::HmacMd5
                | AlgoKind::HmacSha1
                | AlgoKind::HmacSha224
                | AlgoKind::HmacSha256
                | AlgoKind::HmacSha384
                | AlgoKind::HmacSha512
                | AlgoKind::HmacSha3
                | AlgoKind::HmacSm3
                | AlgoKind::HmacRipemd
        )
    }
}

pub struct AlgoSpec {
    pub id: &'static str,
    pub name: &'static str,
    pub kind: AlgoKind,
    /// 期望的 key 字节长度;空表示任意长度 (哈希/HMAC/RC4 等)
    pub key_sizes: &'static [usize],
}

pub const ALGO_SPECS: &[AlgoSpec] = &[
    AlgoSpec { id: "aes-ecb",   name: "AES-ECB",      kind: AlgoKind::AesEcb,   key_sizes: &[16, 24, 32] },
    AlgoSpec { id: "aes-cbc",   name: "AES-CBC",      kind: AlgoKind::AesCbc,   key_sizes: &[16, 24, 32] },
    AlgoSpec { id: "aes-cfb",   name: "AES-CFB",      kind: AlgoKind::AesCfb,   key_sizes: &[16, 24, 32] },
    AlgoSpec { id: "aes-ctr",   name: "AES-CTR",      kind: AlgoKind::AesCtr,   key_sizes: &[16, 24, 32] },
    AlgoSpec { id: "aes-gcm",   name: "AES-GCM",      kind: AlgoKind::AesGcm,   key_sizes: &[16, 32] },
    AlgoSpec { id: "des-ecb",   name: "DES-ECB",      kind: AlgoKind::DesEcb,   key_sizes: &[8] },
    AlgoSpec { id: "des-cbc",   name: "DES-CBC",      kind: AlgoKind::DesCbc,   key_sizes: &[8] },
    AlgoSpec { id: "3des-ecb",  name: "3DES-ECB",     kind: AlgoKind::TdesEcb,  key_sizes: &[24] },
    AlgoSpec { id: "3des-cbc",  name: "3DES-CBC",     kind: AlgoKind::TdesCbc,  key_sizes: &[24] },
    AlgoSpec { id: "sm4-ecb",   name: "SM4-ECB",      kind: AlgoKind::Sm4Ecb,   key_sizes: &[16] },
    AlgoSpec { id: "sm4-cbc",   name: "SM4-CBC",      kind: AlgoKind::Sm4Cbc,   key_sizes: &[16] },
    AlgoSpec { id: "sm4-cfb",   name: "SM4-CFB",      kind: AlgoKind::Sm4Cfb,   key_sizes: &[16] },
    AlgoSpec { id: "rc4",       name: "RC4",          kind: AlgoKind::Rc4,      key_sizes: &[8, 16, 24, 32] },
    AlgoSpec { id: "chacha20",  name: "ChaCha20",     kind: AlgoKind::ChaCha20, key_sizes: &[32] },
    AlgoSpec { id: "md5",       name: "MD5",          kind: AlgoKind::Md5,      key_sizes: &[] },
    AlgoSpec { id: "sha1",      name: "SHA-1",        kind: AlgoKind::Sha1,     key_sizes: &[] },
    AlgoSpec { id: "sha256",    name: "SHA-256",      kind: AlgoKind::Sha256,   key_sizes: &[] },
    AlgoSpec { id: "sha512",    name: "SHA-512",      kind: AlgoKind::Sha512,   key_sizes: &[] },
    AlgoSpec { id: "sm3",       name: "SM3",          kind: AlgoKind::Sm3,      key_sizes: &[] },
    AlgoSpec { id: "ripemd160", name: "RIPEMD-160",   kind: AlgoKind::Ripemd160,key_sizes: &[] },
    AlgoSpec { id: "hmac-md5",    name: "HMAC-MD5",     kind: AlgoKind::HmacMd5,    key_sizes: &[] },
    AlgoSpec { id: "hmac-sha1",   name: "HMAC-SHA-1",   kind: AlgoKind::HmacSha1,   key_sizes: &[] },
    AlgoSpec { id: "hmac-sha224", name: "HMAC-SHA-224", kind: AlgoKind::HmacSha224, key_sizes: &[] },
    AlgoSpec { id: "hmac-sha256", name: "HMAC-SHA-256", kind: AlgoKind::HmacSha256, key_sizes: &[] },
    AlgoSpec { id: "hmac-sha384", name: "HMAC-SHA-384", kind: AlgoKind::HmacSha384, key_sizes: &[] },
    AlgoSpec { id: "hmac-sha512", name: "HMAC-SHA-512", kind: AlgoKind::HmacSha512, key_sizes: &[] },
    AlgoSpec { id: "hmac-sha3",   name: "HMAC-SHA-3",   kind: AlgoKind::HmacSha3,   key_sizes: &[] },
    AlgoSpec { id: "hmac-sm3",    name: "HMAC-SM3",     kind: AlgoKind::HmacSm3,    key_sizes: &[] },
    AlgoSpec { id: "hmac-ripemd", name: "HMAC-RIPEMD",  kind: AlgoKind::HmacRipemd, key_sizes: &[] },
];

pub fn lookup_spec(id: &str) -> Option<&'static AlgoSpec> {
    ALGO_SPECS.iter().find(|s| s.id == id)
}

// ─── 密文解析 ──────────────────────────────────────────────────────

pub fn parse_ciphertext(s: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.is_empty() {
        return Err("密文为空".into());
    }
    // 优先尝试 HEX
    if cleaned.len() % 2 == 0 && cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
        if let Ok(b) = hex::decode(&cleaned) {
            return Ok(b);
        }
    }
    // 退回 Base64 (标准 / URL)
    use base64::Engine;
    if let Ok(b) = base64::engine::general_purpose::STANDARD.decode(&cleaned) {
        return Ok(b);
    }
    if let Ok(b) = base64::engine::general_purpose::URL_SAFE.decode(&cleaned) {
        return Ok(b);
    }
    Err("密文格式无法识别 (HEX / Base64 均失败)".into())
}

// ─── 候选 KEY 提取 ─────────────────────────────────────────────────

#[inline]
fn is_printable_ascii(b: &[u8]) -> bool {
    !b.is_empty() && b.iter().all(|&c| (0x20..=0x7e).contains(&c))
}

/// 多字节 UTF-8 起始字节对应的序列长度 (2/3/4);非起始字节返回 0。
#[inline]
fn utf8_seq_len(c: u8) -> usize {
    match c {
        0xc2..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf4 => 4,
        _ => 0,
    }
}

/// 统计「文本字节」数: 可打印 ASCII (含 \t\n\r) + 构成合法 UTF-8 多字节序列的字节。
///
/// 关键: 随机 AES 输出里高位字节几乎构不成合法 UTF-8 (3 字节字符的概率 ≈ 0.4%),
/// 所以这个计数对乱码依然是强过滤;但中日韩等 UTF-8 文本能被算作文本, 不再误杀。
/// 容忍块首/块尾各一个被截断的多字节字符。
fn text_byte_count(b: &[u8]) -> usize {
    let n = b.len();
    let mut text = 0usize;
    let mut i = 0usize;
    while i < n {
        let c = b[i];
        if c == b'\t' || c == b'\n' || c == b'\r' || (0x20..=0x7e).contains(&c) {
            text += 1;
            i += 1;
            continue;
        }
        let seq = utf8_seq_len(c);
        if seq >= 2 {
            if i + seq <= n && b[i + 1..i + seq].iter().all(|&x| (0x80..=0xbf).contains(&x)) {
                text += seq;
                i += seq;
                continue;
            }
            // 块尾被截断的多字节字符: 计为文本, 结束
            if i + seq > n {
                text += n - i;
                break;
            }
        }
        // 其余 (控制字节 / 孤立高位字节 / 连续字节开头) 视为噪声
        i += 1;
    }
    text
}

/// 文本占比 (见 [`text_byte_count`])。空切片返回 0。
#[inline]
fn text_ratio(b: &[u8]) -> f32 {
    if b.is_empty() {
        0.0
    } else {
        text_byte_count(b) as f32 / b.len() as f32
    }
}

/// 「非控制字符段」定义: 字节 ∈ [0x20..=0x7e] ∪ [0x80..=0xff]
/// (即排除 0x00-0x1f 控制字符)。模仿 HZJQF/help_tool 的
/// `pattern_all = [ -~\x80-\xff]{4,}` 策略。
///
/// 典型进程 dump 30-60% 字节是 0x00 (堆 padding / 对齐填充 / 未初始化内存),
/// 这些字节段被这道滤一次性剔除, 后续滑窗根本不进入。
#[inline]
fn is_segment_byte(b: u8) -> bool {
    b >= 0x20 && b != 0x7f
}

/// 段迭代器: 在 src[range] 范围内, 输出所有长度 ≥ min_len 的连续"非控制字符段"
/// 的相对偏移 (start_in_src, end_in_src) 范围。段之间被 0x00-0x1f / 0x7f 分隔。
struct SegmentIter<'a> {
    src: &'a [u8],
    i: usize,
    end: usize,
    min_len: usize,
}

impl<'a> Iterator for SegmentIter<'a> {
    type Item = (usize, usize);
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            // 跳过控制字符
            while self.i < self.end && !is_segment_byte(self.src[self.i]) {
                self.i += 1;
            }
            if self.i >= self.end {
                return None;
            }
            let s = self.i;
            // 推进直到下一个控制字符
            while self.i < self.end && is_segment_byte(self.src[self.i]) {
                self.i += 1;
            }
            let e = self.i;
            if e - s >= self.min_len {
                return Some((s, e));
            }
            // 段太短, 继续找下一个
        }
    }
}

/// 快速首块过滤: 只解密密文第一个数据块, 检查是否像 ASCII。
/// 错误 key 解密首块得到的是随机字节, 几乎 99.8% 不通过这道筛 →
/// 不进入完整 N 块解密 + PKCS#7 padding 检查的重路径。
///
/// 对随机字节, P(连续 16 个全可打印 ASCII) ≈ 0.002, 所以拒绝率 ~99.8%。
/// 对常见 JSON / query-string 明文, 第一块几乎总是字母+符号, 通过率 100%。
///
/// 注意: 对二进制明文 (e.g. protobuf 字节) 会假阴性, 这种场景需要用户手动禁用。
#[inline]
fn looks_promising_sym(kind: AlgoKind, key: &[u8], ct: &[u8]) -> bool {
    use cipher::generic_array::GenericArray;
    use cipher::{BlockDecrypt, BlockEncrypt, KeyInit};

    #[inline]
    fn ascii_pass(b: &[u8]) -> bool {
        // 75% 阈值, 容忍少量非文本字节。文本 = 可打印 ASCII + 合法 UTF-8 多字节,
        // 所以含中日韩字符的明文块 (e.g. {"name":"韦成遥") 不会被误杀。
        text_byte_count(b) * 4 >= b.len() * 3
    }

    match kind {
        AlgoKind::AesEcb => {
            if ct.len() < 16 {
                return false;
            }
            let mut block: GenericArray<u8, _> =
                *GenericArray::from_slice(&ct[..16]);
            match key.len() {
                16 => match aes::Aes128::new_from_slice(key) {
                    Ok(c) => c.decrypt_block(&mut block),
                    _ => return false,
                },
                24 => match aes::Aes192::new_from_slice(key) {
                    Ok(c) => c.decrypt_block(&mut block),
                    _ => return false,
                },
                32 => match aes::Aes256::new_from_slice(key) {
                    Ok(c) => c.decrypt_block(&mut block),
                    _ => return false,
                },
                _ => return false,
            }
            ascii_pass(block.as_slice())
        }
        AlgoKind::AesCbc => {
            if ct.len() < 32 {
                return false;
            }
            let mut block: GenericArray<u8, _> =
                *GenericArray::from_slice(&ct[16..32]);
            match key.len() {
                16 => match aes::Aes128::new_from_slice(key) {
                    Ok(c) => c.decrypt_block(&mut block),
                    _ => return false,
                },
                24 => match aes::Aes192::new_from_slice(key) {
                    Ok(c) => c.decrypt_block(&mut block),
                    _ => return false,
                },
                32 => match aes::Aes256::new_from_slice(key) {
                    Ok(c) => c.decrypt_block(&mut block),
                    _ => return false,
                },
                _ => return false,
            }
            for i in 0..16 {
                block[i] ^= ct[i];
            }
            ascii_pass(block.as_slice())
        }
        AlgoKind::AesCfb | AlgoKind::AesCtr => {
            // CFB / CTR: P_1 = ENCRYPT(K, IV) XOR C_1
            if ct.len() < 32 {
                return false;
            }
            let mut block: GenericArray<u8, _> =
                *GenericArray::from_slice(&ct[..16]);
            match key.len() {
                16 => match aes::Aes128::new_from_slice(key) {
                    Ok(c) => c.encrypt_block(&mut block),
                    _ => return false,
                },
                24 => match aes::Aes192::new_from_slice(key) {
                    Ok(c) => c.encrypt_block(&mut block),
                    _ => return false,
                },
                32 => match aes::Aes256::new_from_slice(key) {
                    Ok(c) => c.encrypt_block(&mut block),
                    _ => return false,
                },
                _ => return false,
            }
            for i in 0..16 {
                block[i] ^= ct[16 + i];
            }
            ascii_pass(block.as_slice())
        }
        AlgoKind::Sm4Ecb => {
            if ct.len() < 16 || key.len() != 16 {
                return false;
            }
            let mut block: GenericArray<u8, _> =
                *GenericArray::from_slice(&ct[..16]);
            match sm4::Sm4::new_from_slice(key) {
                Ok(c) => c.decrypt_block(&mut block),
                _ => return false,
            }
            ascii_pass(block.as_slice())
        }
        AlgoKind::Sm4Cbc => {
            if ct.len() < 32 || key.len() != 16 {
                return false;
            }
            let mut block: GenericArray<u8, _> =
                *GenericArray::from_slice(&ct[16..32]);
            match sm4::Sm4::new_from_slice(key) {
                Ok(c) => c.decrypt_block(&mut block),
                _ => return false,
            }
            for i in 0..16 {
                block[i] ^= ct[i];
            }
            ascii_pass(block.as_slice())
        }
        AlgoKind::Sm4Cfb => {
            if ct.len() < 32 || key.len() != 16 {
                return false;
            }
            let mut block: GenericArray<u8, _> =
                *GenericArray::from_slice(&ct[..16]);
            match sm4::Sm4::new_from_slice(key) {
                Ok(c) => c.encrypt_block(&mut block),
                _ => return false,
            }
            for i in 0..16 {
                block[i] ^= ct[16 + i];
            }
            ascii_pass(block.as_slice())
        }
        AlgoKind::DesEcb => {
            if ct.len() < 8 || key.len() != 8 {
                return false;
            }
            let mut block: GenericArray<u8, _> =
                *GenericArray::from_slice(&ct[..8]);
            match des::Des::new_from_slice(key) {
                Ok(c) => c.decrypt_block(&mut block),
                _ => return false,
            }
            ascii_pass(block.as_slice())
        }
        AlgoKind::DesCbc => {
            if ct.len() < 16 || key.len() != 8 {
                return false;
            }
            let mut block: GenericArray<u8, _> =
                *GenericArray::from_slice(&ct[8..16]);
            match des::Des::new_from_slice(key) {
                Ok(c) => c.decrypt_block(&mut block),
                _ => return false,
            }
            for i in 0..8 {
                block[i] ^= ct[i];
            }
            ascii_pass(block.as_slice())
        }
        AlgoKind::TdesEcb => {
            if ct.len() < 8 || key.len() != 24 {
                return false;
            }
            let mut block: GenericArray<u8, _> =
                *GenericArray::from_slice(&ct[..8]);
            match des::TdesEde3::new_from_slice(key) {
                Ok(c) => c.decrypt_block(&mut block),
                _ => return false,
            }
            ascii_pass(block.as_slice())
        }
        AlgoKind::TdesCbc => {
            if ct.len() < 16 || key.len() != 24 {
                return false;
            }
            let mut block: GenericArray<u8, _> =
                *GenericArray::from_slice(&ct[8..16]);
            match des::TdesEde3::new_from_slice(key) {
                Ok(c) => c.decrypt_block(&mut block),
                _ => return false,
            }
            for i in 0..8 {
                block[i] ^= ct[i];
            }
            ascii_pass(block.as_slice())
        }
        // GCM 自带 tag 校验, RC4/ChaCha20 无块结构 → 不预筛, 直走完整 try_decrypt
        _ => true,
    }
}

/// 熵预过滤: 真实加密 key 几乎都是高熵随机字节, 而 dump 里大量的全零、全相同、
/// 顺序累加、低熵填充这类窗口绝不可能是 key。先一票否决能省掉后面所有重活。
///
/// 拒绝条件 (任一满足):
///  * 所有字节相同 (00 00 00 ..., FF FF FF ...)
///  * 0x00 占比 >= 50%
///  * 唯一字节数 < win.len()/3 (低熵: AAABBB, 01010101 等)
#[inline]
fn passes_entropy_filter(win: &[u8]) -> bool {
    if win.is_empty() {
        return false;
    }
    let first = win[0];
    let mut all_same = true;
    let mut nulls = 0usize;
    // 64 位 bitset 标记看到了哪些字节 (0..255)
    let mut bits = [0u64; 4];
    for &b in win {
        if b != first {
            all_same = false;
        }
        if b == 0 {
            nulls += 1;
        }
        bits[(b >> 6) as usize] |= 1u64 << (b & 0x3F);
    }
    if all_same {
        return false;
    }
    if nulls * 2 >= win.len() {
        return false;
    }
    let distinct: u32 = bits.iter().map(|b| b.count_ones()).sum();
    let min_distinct = ((win.len() as u32) / 3).max(2);
    distinct >= min_distinct
}

/// dump 字符串扫描: 抓出所有连续可打印 ASCII 段 (典型用法同 `strings` 命令)。
/// 用于"密文是哈希值, 想找明文"的反查场景: 明文长度未知, 但通常作为 C 字符串
/// 或 token 形式存在于内存里, 被 \0 / 控制字符截断。
pub fn extract_strings(
    sources: &[Arc<Vec<u8>>],
    min_len: usize,
    max_len: usize,
    max_strings: usize,
    stop: Option<&AtomicBool>,
    tx: Option<&Sender<EngineMsg>>,
) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    let mut seen: HashSet<u64> = HashSet::with_capacity(1 << 16);
    let mut last_report = Instant::now();

    'sources: for (src_idx, src) in sources.iter().enumerate() {
        let mut start: Option<usize> = None;
        for (i, &b) in src.iter().enumerate() {
            let is_print = (0x20..=0x7e).contains(&b);
            if is_print {
                if start.is_none() {
                    start = Some(i);
                }
            } else if let Some(s) = start.take() {
                let len = i - s;
                if len >= min_len && len <= max_len {
                    let win = &src[s..i];
                    let h = fast_hash(win);
                    if seen.insert(h) {
                        out.push(win.to_vec());
                        if out.len() >= max_strings {
                            if let Some(tx) = tx {
                                log(
                                    tx,
                                    MsgLvl::Warn,
                                    format!("字符串候选达上限 {}, 停止扫描", max_strings),
                                    true,
                                );
                            }
                            break 'sources;
                        }
                    }
                }
            }

            // 周期性 check stop + 报进度
            if i & 0x7F_FFFF == 0 && i > 0 {
                if let Some(s) = stop {
                    if s.load(Ordering::Relaxed) {
                        break 'sources;
                    }
                }
                if last_report.elapsed() >= Duration::from_millis(400) {
                    if let Some(tx) = tx {
                        log(
                            tx,
                            MsgLvl::Info,
                            format!(
                                "字符串扫描 · 源 {}/{} · 已抓 {} 段",
                                src_idx + 1,
                                sources.len(),
                                out.len()
                            ),
                            false,
                        );
                    }
                    last_report = Instant::now();
                }
            }
        }
        // 处理尾段
        if let Some(s) = start {
            let len = src.len() - s;
            if len >= min_len && len <= max_len {
                let win = &src[s..];
                let h = fast_hash(win);
                if seen.insert(h) {
                    out.push(win.to_vec());
                }
            }
        }
    }

    out
}

/// 流式哈希反查: 一遍扫 dump, 边提取 ASCII 段边算所有哈希算法 + 比对密文。
///
/// 优势 vs "先 extract_strings 再 per-algo 迭代":
///  * 不存中间字符串到 Vec, 内存只有 HashSet&lt;u64&gt; 去重表
///  * 没有 MAX_STRINGS 上限, 可以跑完整个 3GB+ 文件
///  * 一遍扫描里把所有启用的哈希算法都顺手算了 (顺序访问, cache 友好)
///  * 命中即发出, UI 可以实时看到命中
///
/// 返回命中次数。
pub fn streaming_hash_match(
    sources: &[Arc<Vec<u8>>],
    ct: &[u8],
    hash_kinds: &[(AlgoKind, &'static str)],
    min_len: usize,
    max_len: usize,
    stop: &AtomicBool,
    tx: &Sender<EngineMsg>,
    t0: Instant,
) -> usize {
    let mut seen: HashSet<u64> = HashSet::with_capacity(1 << 20);
    let mut hits: usize = 0;
    let mut scanned_strings: u64 = 0;
    let mut last_report = Instant::now();

    let try_match = |win: &[u8],
                     seen: &mut HashSet<u64>,
                     hits: &mut usize,
                     scanned_strings: &mut u64,
                     tx: &Sender<EngineMsg>|
     -> () {
        let h = fast_hash(win);
        if !seen.insert(h) {
            return;
        }
        *scanned_strings += 1;
        for &(kind, name) in hash_kinds {
            if try_hash(kind, win, ct).is_some() {
                *hits += 1;
                let preview = make_preview(win);
                log(
                    tx,
                    MsgLvl::Ok,
                    format!("命中 {} · 明文 = {}", name, preview),
                    true,
                );
                send(
                    tx,
                    EngineMsg::Hit {
                        algo: name.to_string(),
                        key_hex: format!("(dump 字符串, {} 字节)", win.len()),
                        iv_hex: None,
                        plain_preview: Some(preview),
                        plain_full: Some(win.to_vec()),
                        reason: "dump 字符串 hash 反查".to_string(),
                        elapsed_ms: t0.elapsed().as_millis() as u64,
                    },
                );
            }
        }
    };

    // 哈希反查的"文本字节": 0x20-0x7e 之外, 还允许 0x09/0x0a/0x0d。
    // HTTP request body / JSON / 表单 form-data 这类被 hash 的明文经常含 \n \r \t,
    // 如果只认 0x20-0x7e 会被换行切碎导致整段进不了 hash 比对。
    #[inline]
    fn is_hash_text_byte(b: u8) -> bool {
        matches!(b, 0x09 | 0x0a | 0x0d) || (0x20..=0x7e).contains(&b)
    }

    let total_bytes: u64 = sources.iter().map(|s| s.len() as u64).sum::<u64>().max(1);
    let mut bytes_done_prior: u64 = 0;
    'sources: for (src_idx, src_arc) in sources.iter().enumerate() {
        let src: &[u8] = src_arc.as_slice();
        let mut start: Option<usize> = None;
        for (i, &b) in src.iter().enumerate() {
            let is_print = is_hash_text_byte(b);
            if is_print {
                if start.is_none() {
                    start = Some(i);
                }
            } else if let Some(s) = start.take() {
                let len = i - s;
                if len >= min_len && len <= max_len {
                    try_match(
                        &src[s..i],
                        &mut seen,
                        &mut hits,
                        &mut scanned_strings,
                        tx,
                    );
                }
            }

            // 周期性 stop / progress
            if i & 0x7F_FFFF == 0 && i > 0 {
                if stop.load(Ordering::Relaxed) {
                    break 'sources;
                }
                let pct = ((bytes_done_prior + i as u64) as f64 / total_bytes as f64
                    * 100.0) as f32;
                send(
                    tx,
                    EngineMsg::Progress {
                        pct,
                        current: format!("流式哈希反查 {}/{}", src_idx + 1, sources.len()),
                    },
                );
                if last_report.elapsed() >= Duration::from_millis(400) {
                    log(
                        tx,
                        MsgLvl::Info,
                        format!(
                            "流式哈希反查 · 源 {}/{} · 已检 {} 字符串 · 命中 {}",
                            src_idx + 1,
                            sources.len(),
                            scanned_strings,
                            hits
                        ),
                        false,
                    );
                    last_report = Instant::now();
                }
            }
        }
        bytes_done_prior += src.len() as u64;
        // 尾段
        if let Some(s) = start {
            let len = src.len() - s;
            if len >= min_len && len <= max_len {
                try_match(
                    &src[s..],
                    &mut seen,
                    &mut hits,
                    &mut scanned_strings,
                    tx,
                );
            }
        }
    }

    // 第二遍: UTF-16 LE 扫描。Windows 进程里 .NET / WinRT / 大量 Win32 API 的
    // 字符串都以 UTF-16 LE 存储 (每个 ASCII 字符后跟一个 0x00)。第一遍按
    // 0x20-0x7e 切分会把这种串在每个 0x00 处切碎, 整段拼接的明文 (HTTP body /
    // JSON) 永远进不了 hash 反查。这里把"ASCII 字符 + 0x00"成对的连续段重新
    // 抽出来作为候选。
    let utf16_scanned_before = scanned_strings;
    bytes_done_prior = 0; // 复用 total_bytes 作分母, 重置已完成字节量
    'sources16: for (src_idx, src_arc) in sources.iter().enumerate() {
        let src: &[u8] = src_arc.as_slice();
        let n = src.len();
        let mut i = 0usize;
        while i + 1 < n {
            // 在 i 处尝试识别 UTF-16 LE ASCII run
            let mut j = i;
            while j + 1 < n {
                let c = src[j];
                let h = src[j + 1];
                if is_hash_text_byte(c) && h == 0x00 {
                    j += 2;
                } else {
                    break;
                }
            }
            let chars = (j - i) / 2;
            if chars >= min_len {
                if chars <= max_len {
                    let mut bytes: Vec<u8> = Vec::with_capacity(chars);
                    let mut k = i;
                    while k < j {
                        bytes.push(src[k]);
                        k += 2;
                    }
                    try_match(
                        &bytes,
                        &mut seen,
                        &mut hits,
                        &mut scanned_strings,
                        tx,
                    );
                }
                i = j;
            } else {
                i += 1;
            }

            // 周期性 stop / progress
            if i & 0x7F_FFFF == 0 && i > 0 {
                if stop.load(Ordering::Relaxed) {
                    break 'sources16;
                }
                let pct = ((bytes_done_prior + i as u64) as f64 / total_bytes as f64
                    * 100.0) as f32;
                send(
                    tx,
                    EngineMsg::Progress {
                        pct,
                        current: format!(
                            "流式哈希反查 (UTF-16) {}/{}",
                            src_idx + 1,
                            sources.len()
                        ),
                    },
                );
            }
        }
        bytes_done_prior += src.len() as u64;
    }

    log(
        tx,
        MsgLvl::Info,
        format!(
            "流式哈希反查完成 · 共扫描 {} 个去重后字符串 (UTF-16 二遍补 {} 个) · 命中 {} 项",
            scanned_strings,
            scanned_strings - utf16_scanned_before,
            hits
        ),
        false,
    );
    hits
}

/// 大数据量去重: 用 u64 内容哈希集合替代 HashSet&lt;Vec&lt;u8&gt;&gt;。
/// 极低概率假阳性(同一 key 被认为重复而漏过), 但对推算工具不致命。
#[inline]
fn fast_hash(b: &[u8]) -> u64 {
    let mut h = DefaultHasher::new();
    b.hash(&mut h);
    h.finish()
}

/// 流式对称 + HMAC 扫描: 一遍扫 dump, 边提取窗口边对 (对称解密, HMAC 反查) 一并测试。
///
/// 优点 vs "extract_candidates + per-algo iterate":
///  * 不存中间候选 Vec, 内存只有 per-worker HashSet&lt;u64&gt; 去重表
///  * 没有 5M 候选上限, 可扫完完整 dump (4 GB 级别也 OK)
///  * 一遍扫描里把所有适配长度的对称算法 + 所有 HMAC 算法都顺手算了
///  * 用 rayon for_each_with 把 (source, length) 工作项并行到全部核
///
/// 返回总命中次数。
pub fn streaming_dump_match(
    sources: &[Arc<Vec<u8>>],
    ct: &[u8],
    sym_specs: &[&'static AlgoSpec],
    hmac_specs: &[&'static AlgoSpec],
    hmac_lens: &[usize],
    plain_contains: &str,
    known_plaintext: &[u8],
    deep_search: bool,
    ascii_only: bool,
    stop: &AtomicBool,
    tx: &Sender<EngineMsg>,
    t0: Instant,
) -> usize {
    // 按 key 长度分组对称算法
    let mut sym_by_len: HashMap<usize, Vec<(AlgoKind, &'static str)>> = HashMap::new();
    let mut all_lens: HashSet<usize> = HashSet::new();
    for spec in sym_specs {
        for &len in spec.key_sizes {
            all_lens.insert(len);
            sym_by_len
                .entry(len)
                .or_default()
                .push((spec.kind, spec.name));
        }
    }
    let hmac_active = !hmac_specs.is_empty() && !known_plaintext.is_empty();
    if hmac_active {
        for &len in hmac_lens {
            all_lens.insert(len);
        }
    }
    if all_lens.is_empty() {
        return 0;
    }
    let hmac_pairs: Vec<(AlgoKind, &'static str)> =
        hmac_specs.iter().map(|s| (s.kind, s.name)).collect();

    let hits = AtomicUsize::new(0);
    let scanned = AtomicUsize::new(0);
    let chunks_done = AtomicUsize::new(0);
    // IV 恢复全 dump 扫描代价不小, 整个任务只做一次 (首个「首块未知」命中触发)
    let iv_search_done = AtomicBool::new(false);

    // 工作项: (源索引, 起始偏移, 结束偏移, 长度)
    // 每个 chunk = 8 MB 起始范围, rayon 自动负载均衡到所有线程
    const CHUNK_BYTES: usize = 8 * 1024 * 1024;
    let mut work: Vec<(usize, usize, usize, usize)> = Vec::new();
    for (si, src_arc) in sources.iter().enumerate() {
        let n = src_arc.len();
        for &len in all_lens.iter() {
            if len == 0 || len > n {
                continue;
            }
            let max_start_plus_1 = n - len + 1;
            let mut s = 0usize;
            while s < max_start_plus_1 {
                let e = (s + CHUNK_BYTES).min(max_start_plus_1);
                work.push((si, s, e, len));
                s = e;
            }
        }
    }
    let total_chunks = work.len().max(1);
    log(
        tx,
        MsgLvl::Info,
        format!(
            "流式扫描切片: {} 个 {}MB chunk · 跨 {} 长度 ({:?}) · 并行到 rayon 池",
            work.len(),
            CHUNK_BYTES / 1024 / 1024,
            all_lens.len(),
            {
                let mut v: Vec<usize> = all_lens.iter().copied().collect();
                v.sort();
                v
            }
        ),
        false,
    );

    work.par_iter()
        .for_each_with(tx.clone(), |tx_local, &(si, start_start, end_start, len)| {
            let src = sources[si].as_slice();
            let step = if deep_search { 1 } else { (len / 2).max(4) };
            let empty: Vec<(AlgoKind, &'static str)> = Vec::new();
            let sym_for_len: &[(AlgoKind, &'static str)] = sym_by_len
                .get(&len)
                .map(Vec::as_slice)
                .unwrap_or(&empty);
            // chunk 本地 dedup; 跨 chunk 同样窗口可能多算几次, 但避免了全局锁
            // 初始容量调大以减少 rehash 次数 (对一个 8 MB chunk 的典型 unique 数量)
            let mut local_seen: HashSet<u64> = HashSet::with_capacity(1 << 19);
            let mut local_scanned: u64 = 0;

            // 段过滤: 只在 [0x20-0x7e \x80-0xff]+ 段内滑窗。0x00 大块填充、
            // 控制字符区整段跳过, 2-5× 减少候选量。借鉴 HZJQF/help_tool。
            let seg_end_cap = end_start.min(src.len());
            let segments = SegmentIter {
                src,
                i: start_start,
                end: seg_end_cap,
                min_len: len.max(4),
            };

            for (seg_start, seg_end) in segments {
                let mut start = seg_start;
                while start + len <= seg_end {
                    local_scanned += 1;

                    // stop 频繁检查 (响应时间 ~1s); 进度日志稀疏发 (避免刷屏)
                    if (local_scanned & 0x3FFF) == 0 {
                        if stop.load(Ordering::Relaxed) {
                            scanned.fetch_add(local_scanned as usize, Ordering::Relaxed);
                            return;
                        }
                        if (local_scanned & 0xFF_FFFF) == 0 {
                            let total = scanned
                                .fetch_add(local_scanned as usize, Ordering::Relaxed)
                                + local_scanned as usize;
                            log(
                                tx_local,
                                MsgLvl::Info,
                                format!(
                                    "流式扫描 · len={} · 累计 {} M 窗口 · 命中 {}",
                                    len,
                                    total / 1_000_000,
                                    hits.load(Ordering::Relaxed)
                                ),
                                false,
                            );
                            local_scanned = 0;
                        }
                    }

                    let win = &src[start..start + len];
                    start += step;

                    if ascii_only && !is_printable_ascii(win) {
                        continue;
                    }
                    // 熵预过滤 (段过滤后再细筛: 段内仍可能有低熵子串)
                    if !passes_entropy_filter(win) {
                        continue;
                    }
                    let h = fast_hash(win);
                    if !local_seen.insert(h) {
                        continue;
                    }

                    // 对称解密尝试
                    for &(kind, name) in sym_for_len {
                        // 快速首块过滤: 99% 错误 key 在这里被淘汰, 不进完整解密
                        if !looks_promising_sym(kind, win, ct) {
                            continue;
                        }
                        // 枚举各 IV 约定的解密结果, 选「最可信」的一条。关键: 关键字/明文
                        // 尾部在两种约定里都能命中 (它们共享首块之后的字节), 不能据此偏向
                        // 前置 IV —— 否则会把真首块当 IV 吃掉。正确判据是「明文是否完整」:
                        //  · 完整 (去掉 skip 后以 {/[ 开头) → 真前置 IV/真首块, 取 skip 最小的;
                        //  · 都不完整 → 真无前置 IV, 取 skip 最大的 (它能反查 IV 补回首块)。
                        let mut cands: Vec<(DecryptAttempt, HitMeta)> = decrypt_attempts(kind, win, ct)
                            .into_iter()
                            .filter_map(|att| {
                                judge_hit_inner(&att.plain, plain_contains, att.judge_skip)
                                    .map(|m| (att, m))
                            })
                            .collect();
                        if cands.is_empty() {
                            continue;
                        }
                        cands.sort_by_key(|(att, _)| {
                            if attempt_is_complete(att) {
                                (0i32, att.judge_skip as i32) // 完整: skip 小者优先
                            } else {
                                (1i32, -(att.judge_skip as i32)) // 不完整: skip 大者优先
                            }
                        });
                        let (att, meta) = cands.into_iter().next().unwrap();

                        hits.fetch_add(1, Ordering::Relaxed);

                    // 首块未知 (无前置 IV): 整个任务首次命中时, 在 dump 里找回真实 IV,
                    // 把乱码首块补成完整明文。
                    let mut iv_hex = att.iv_hex.clone();
                    let mut full_plain = att.plain.clone();
                    let mut reason = meta.reason.to_string();
                    let mut skip = att.judge_skip;
                    if skip > 0
                        && iv_search_done
                            .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
                            .is_ok()
                    {
                        log(tx_local, MsgLvl::Info, "首块未知 · 正在 dump 中反查 IV…", false);
                        if let Some((iv, recovered)) =
                            recover_cbc_iv(kind, win, ct, &att.plain, sources, stop)
                        {
                            iv_hex = Some(hex::encode(&iv));
                            full_plain = recovered;
                            // 去掉判据里的「(首块未知)」尾巴, 换成「IV 已恢复」
                            reason = format!("{} · IV 已恢复", meta.reason.replace("(首块未知)", ""));
                            skip = 0;
                            log(
                                tx_local,
                                MsgLvl::Ok,
                                format!("IV 反查成功: {}", hex::encode(&iv)),
                                true,
                            );
                        } else {
                            if !reason.contains("首块未知") {
                                reason = format!("{} · 首块未知", reason);
                            }
                            log(tx_local, MsgLvl::Warn, "IV 未在 dump 中找到, 首块仍未知", false);
                        }
                    }

                    // 首块仍未知时预览跳过乱码前缀, 并标注
                    let preview = if skip > 0 && full_plain.len() > skip {
                        format!(
                            "⟨前 {}B 首块未知⟩ {}",
                            skip,
                            make_preview(&full_plain[skip..])
                        )
                    } else {
                        make_preview(&full_plain)
                    };
                    log(
                        tx_local,
                        MsgLvl::Ok,
                        format!("命中 {} · key={} · {}", name, hex_short(win), reason),
                        true,
                    );
                    send(
                        tx_local,
                        EngineMsg::Hit {
                            algo: algo_display_name(kind, win.len()),
                            key_hex: format_key_hex(win),
                            iv_hex,
                            plain_preview: Some(preview),
                            plain_full: Some(full_plain),
                            reason,
                            elapsed_ms: t0.elapsed().as_millis() as u64,
                        },
                    );
                }

                // HMAC 反查尝试
                if hmac_active {
                    for &(kind, name) in &hmac_pairs {
                        if try_hmac(kind, win, known_plaintext, ct).is_some() {
                            hits.fetch_add(1, Ordering::Relaxed);
                            log(
                                tx_local,
                                MsgLvl::Ok,
                                format!("命中 {} · key={}", name, hex_short(win)),
                                true,
                            );
                            send(
                                tx_local,
                                EngineMsg::Hit {
                                    algo: name.to_string(),
                                    key_hex: format_key_hex(win),
                                    iv_hex: None,
                                    plain_preview: Some(make_preview(known_plaintext)),
                                    plain_full: Some(known_plaintext.to_vec()),
                                    reason: "HMAC 指纹".to_string(),
                                    elapsed_ms: t0.elapsed().as_millis() as u64,
                                },
                            );
                        }
                    }
                }
                } // end inner while (window slide)
            } // end 'segments for loop
            scanned.fetch_add(local_scanned as usize, Ordering::Relaxed);

            // 每完成一个 chunk 就推一次进度。total_chunks 可能上千, 这里限到每 4
            // 个 chunk 上报一次, 既丝滑又不刷爆 channel。
            let done = chunks_done.fetch_add(1, Ordering::Relaxed) + 1;
            if (done & 0x3) == 0 || done == total_chunks {
                let pct = (done as f32 / total_chunks as f32) * 100.0;
                send(
                    tx_local,
                    EngineMsg::Progress {
                        pct,
                        current: format!("流式扫描 {}/{}", done, total_chunks),
                    },
                );
            }
        });

    let h = hits.load(Ordering::Relaxed);
    let s = scanned.load(Ordering::Relaxed);
    log(
        tx,
        MsgLvl::Info,
        format!("流式对称/HMAC 扫描完成 · 共 {} 窗口 · 命中 {} 项", s, h),
        false,
    );
    h
}

pub struct ExtractOpts<'a> {
    pub lens: &'a [usize],
    pub ascii_only: bool,
    pub dedup: bool,
    pub key_encode: bool,
    pub deep_search: bool,
    pub max_candidates: usize,
    pub stop: Option<&'a AtomicBool>,
    pub tx: Option<&'a Sender<EngineMsg>>,
}

pub fn extract_candidates(sources: &[Arc<Vec<u8>>], opts: ExtractOpts<'_>) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    let mut seen: HashSet<u64> = HashSet::with_capacity(1 << 16);
    let cap = opts.max_candidates.max(1);
    let mut last_report = Instant::now();
    let mut scanned_bytes: u64 = 0;

    'sources: for (src_idx, src) in sources.iter().enumerate() {
        for &len in opts.lens {
            if len == 0 || len > src.len() {
                continue;
            }
            // 非深搜: step = max(len/2, 4), 大致按对齐扫描, 量级降一两个数量级
            // 深搜: 每字节起点
            let step = if opts.deep_search { 1 } else { (len / 2).max(4) };
            let mut start = 0usize;
            while start + len <= src.len() {
                // 周期性 (每 ~16 MB) check stop + 上报进度, 让长时间运行可中断
                if scanned_bytes & 0xFF_FFFF == 0 && scanned_bytes > 0 {
                    if let Some(s) = opts.stop {
                        if s.load(Ordering::Relaxed) {
                            if let Some(tx) = opts.tx {
                                log(tx, MsgLvl::Warn, "提取阶段收到停止信号", true);
                            }
                            break 'sources;
                        }
                    }
                    if last_report.elapsed() >= Duration::from_millis(400) {
                        if let Some(tx) = opts.tx {
                            log(
                                tx,
                                MsgLvl::Info,
                                format!(
                                    "扫描进度 · 数据源 {}/{} · 已生成 {} 候选",
                                    src_idx + 1,
                                    sources.len(),
                                    out.len()
                                ),
                                false,
                            );
                        }
                        last_report = Instant::now();
                    }
                }

                let win = &src[start..start + len];
                start += step;
                scanned_bytes = scanned_bytes.wrapping_add(step as u64);

                if opts.ascii_only && !is_printable_ascii(win) {
                    continue;
                }
                if opts.dedup {
                    let h = fast_hash(win);
                    if !seen.insert(h) {
                        continue;
                    }
                }
                out.push(win.to_vec());
                if out.len() >= cap {
                    if let Some(tx) = opts.tx {
                        log(
                            tx,
                            MsgLvl::Warn,
                            format!("候选 KEY 达上限 {}, 提前停止扫描", cap),
                            true,
                        );
                    }
                    break 'sources;
                }
            }
        }
    }

    // 编码 KEY: 把可见 ASCII 窗口当作 hex / base64 字符串再解码一次,
    // 用于抓住 "key 以字符串形式存储" 的场景
    if opts.key_encode && out.len() < cap {
        use base64::Engine;
        let snapshot = out.clone();
        for c in &snapshot {
            if out.len() >= cap {
                break;
            }
            let Ok(s) = std::str::from_utf8(c) else { continue };
            if s.len() % 2 == 0 && s.chars().all(|ch| ch.is_ascii_hexdigit()) {
                if let Ok(b) = hex::decode(s) {
                    if !b.is_empty()
                        && (!opts.dedup || seen.insert(fast_hash(&b)))
                    {
                        out.push(b);
                    }
                }
            }
            if let Ok(b) = base64::engine::general_purpose::STANDARD.decode(s) {
                if !b.is_empty() && (!opts.dedup || seen.insert(fast_hash(&b))) {
                    out.push(b);
                }
            }
        }
    }

    out
}

// ─── 解密单次尝试 ──────────────────────────────────────────────────

/// 对 (kind, key, ct) 尝试一次解密。
/// IV / nonce 约定: 取密文头部相应字节;ECB 无 IV。
/// 解密成功 + 通过 PKCS#7 解填充 + 长度 > 0 才返回 Some。
pub fn try_decrypt(kind: AlgoKind, key: &[u8], ct: &[u8]) -> Option<Vec<u8>> {
    const B16: usize = 16;
    const B8: usize = 8;
    match kind {
        AlgoKind::AesEcb => {
            if ct.is_empty() || ct.len() % B16 != 0 {
                return None;
            }
            let mut buf = vec![0u8; ct.len()];
            let pt = match key.len() {
                16 => Aes128EcbDec::new_from_slice(key).ok()?
                    .decrypt_padded_b2b_mut::<Pkcs7>(ct, &mut buf).ok()?,
                24 => Aes192EcbDec::new_from_slice(key).ok()?
                    .decrypt_padded_b2b_mut::<Pkcs7>(ct, &mut buf).ok()?,
                32 => Aes256EcbDec::new_from_slice(key).ok()?
                    .decrypt_padded_b2b_mut::<Pkcs7>(ct, &mut buf).ok()?,
                _ => return None,
            };
            Some(pt.to_vec())
        }
        AlgoKind::AesCbc => {
            if ct.len() < 2 * B16 || (ct.len() - B16) % B16 != 0 {
                return None;
            }
            let (iv, data) = ct.split_at(B16);
            let mut buf = vec![0u8; data.len()];
            let pt = match key.len() {
                16 => Aes128CbcDec::new_from_slices(key, iv).ok()?
                    .decrypt_padded_b2b_mut::<Pkcs7>(data, &mut buf).ok()?,
                24 => Aes192CbcDec::new_from_slices(key, iv).ok()?
                    .decrypt_padded_b2b_mut::<Pkcs7>(data, &mut buf).ok()?,
                32 => Aes256CbcDec::new_from_slices(key, iv).ok()?
                    .decrypt_padded_b2b_mut::<Pkcs7>(data, &mut buf).ok()?,
                _ => return None,
            };
            Some(pt.to_vec())
        }
        AlgoKind::AesCfb => {
            if ct.len() < B16 {
                return None;
            }
            let (iv, data) = ct.split_at(B16);
            let mut out = data.to_vec();
            match key.len() {
                16 => Aes128CfbDec::new_from_slices(key, iv).ok()?.decrypt(&mut out),
                24 => Aes192CfbDec::new_from_slices(key, iv).ok()?.decrypt(&mut out),
                32 => Aes256CfbDec::new_from_slices(key, iv).ok()?.decrypt(&mut out),
                _ => return None,
            }
            Some(out)
        }
        AlgoKind::AesCtr => {
            if ct.len() < B16 {
                return None;
            }
            let (iv, data) = ct.split_at(B16);
            let mut out = data.to_vec();
            match key.len() {
                16 => Aes128CtrCipher::new_from_slices(key, iv).ok()?.apply_keystream(&mut out),
                24 => Aes192CtrCipher::new_from_slices(key, iv).ok()?.apply_keystream(&mut out),
                32 => Aes256CtrCipher::new_from_slices(key, iv).ok()?.apply_keystream(&mut out),
                _ => return None,
            }
            Some(out)
        }
        AlgoKind::AesGcm => {
            use aes_gcm::aead::Aead;
            use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};
            const NONCE: usize = 12;
            if ct.len() < NONCE + 16 {
                return None;
            }
            let nonce = Nonce::from_slice(&ct[..NONCE]);
            let data = &ct[NONCE..];
            match key.len() {
                16 => Aes128Gcm::new_from_slice(key).ok()?.decrypt(nonce, data).ok(),
                32 => Aes256Gcm::new_from_slice(key).ok()?.decrypt(nonce, data).ok(),
                _ => None,
            }
        }
        AlgoKind::DesEcb => {
            if key.len() != 8 || ct.is_empty() || ct.len() % B8 != 0 {
                return None;
            }
            let mut buf = vec![0u8; ct.len()];
            let pt = DesEcbDec::new_from_slice(key).ok()?
                .decrypt_padded_b2b_mut::<Pkcs7>(ct, &mut buf).ok()?;
            Some(pt.to_vec())
        }
        AlgoKind::DesCbc => {
            if key.len() != 8 || ct.len() < 2 * B8 || (ct.len() - B8) % B8 != 0 {
                return None;
            }
            let (iv, data) = ct.split_at(B8);
            let mut buf = vec![0u8; data.len()];
            let pt = DesCbcDec::new_from_slices(key, iv).ok()?
                .decrypt_padded_b2b_mut::<Pkcs7>(data, &mut buf).ok()?;
            Some(pt.to_vec())
        }
        AlgoKind::TdesEcb => {
            if key.len() != 24 || ct.is_empty() || ct.len() % B8 != 0 {
                return None;
            }
            let mut buf = vec![0u8; ct.len()];
            let pt = TdesEcbDec::new_from_slice(key).ok()?
                .decrypt_padded_b2b_mut::<Pkcs7>(ct, &mut buf).ok()?;
            Some(pt.to_vec())
        }
        AlgoKind::TdesCbc => {
            if key.len() != 24 || ct.len() < 2 * B8 || (ct.len() - B8) % B8 != 0 {
                return None;
            }
            let (iv, data) = ct.split_at(B8);
            let mut buf = vec![0u8; data.len()];
            let pt = TdesCbcDec::new_from_slices(key, iv).ok()?
                .decrypt_padded_b2b_mut::<Pkcs7>(data, &mut buf).ok()?;
            Some(pt.to_vec())
        }
        AlgoKind::Sm4Ecb => {
            if key.len() != 16 || ct.is_empty() || ct.len() % B16 != 0 {
                return None;
            }
            let mut buf = vec![0u8; ct.len()];
            let pt = Sm4EcbDec::new_from_slice(key).ok()?
                .decrypt_padded_b2b_mut::<Pkcs7>(ct, &mut buf).ok()?;
            Some(pt.to_vec())
        }
        AlgoKind::Sm4Cbc => {
            if key.len() != 16 || ct.len() < 2 * B16 || (ct.len() - B16) % B16 != 0 {
                return None;
            }
            let (iv, data) = ct.split_at(B16);
            let mut buf = vec![0u8; data.len()];
            let pt = Sm4CbcDec::new_from_slices(key, iv).ok()?
                .decrypt_padded_b2b_mut::<Pkcs7>(data, &mut buf).ok()?;
            Some(pt.to_vec())
        }
        AlgoKind::Sm4Cfb => {
            if key.len() != 16 || ct.len() < B16 {
                return None;
            }
            let (iv, data) = ct.split_at(B16);
            let mut out = data.to_vec();
            Sm4CfbDec::new_from_slices(key, iv).ok()?.decrypt(&mut out);
            Some(out)
        }
        AlgoKind::Rc4 => {
            // rc4 crate 通过 typenum 限定 key 长度,只能枚举常见尺寸
            use rc4::consts::{U16, U24, U32, U5, U8};
            use rc4::Rc4;
            let mut out = ct.to_vec();
            match key.len() {
                5 => {
                    let mut c = Rc4::<U5>::new_from_slice(key).ok()?;
                    c.apply_keystream(&mut out);
                }
                8 => {
                    let mut c = Rc4::<U8>::new_from_slice(key).ok()?;
                    c.apply_keystream(&mut out);
                }
                16 => {
                    let mut c = Rc4::<U16>::new_from_slice(key).ok()?;
                    c.apply_keystream(&mut out);
                }
                24 => {
                    let mut c = Rc4::<U24>::new_from_slice(key).ok()?;
                    c.apply_keystream(&mut out);
                }
                32 => {
                    let mut c = Rc4::<U32>::new_from_slice(key).ok()?;
                    c.apply_keystream(&mut out);
                }
                _ => return None,
            }
            Some(out)
        }
        AlgoKind::ChaCha20 => {
            use chacha20::ChaCha20;
            if key.len() != 32 || ct.len() < 12 {
                return None;
            }
            let (iv, data) = ct.split_at(12);
            let mut out = data.to_vec();
            ChaCha20::new_from_slices(key, iv).ok()?.apply_keystream(&mut out);
            Some(out)
        }
        // 哈希 / HMAC 不走 try_decrypt
        _ => None,
    }
}

/// CBC 系算法的「无前置 IV」约定: 整段密文都是密文 (不切掉前 16/8 字节当 IV),
/// 用全零 IV 解密。
///
/// 原理: CBC 解密里 IV 只异或到第一个明文块, 第 2 块往后只依赖前一个密文块,
/// 与 IV 无关。所以即使不知道真实 IV, 只要 key 对, 除首块外的明文全部正确,
/// PKCS#7 padding (在最后一块) 也能正常校验通过。首块是乱码, 判据需跳过。
/// 真实 IV 可在已知首块明文后用 `IV = Decrypt(K, C_1) XOR P_1` 反推, 这里不做。
fn try_decrypt_cbc_zero_iv(kind: AlgoKind, key: &[u8], ct: &[u8]) -> Option<Vec<u8>> {
    const B16: usize = 16;
    const B8: usize = 8;
    match kind {
        AlgoKind::AesCbc => {
            if ct.len() < 2 * B16 || ct.len() % B16 != 0 {
                return None;
            }
            let iv = [0u8; B16];
            let mut buf = vec![0u8; ct.len()];
            let pt = match key.len() {
                16 => Aes128CbcDec::new_from_slices(key, &iv).ok()?
                    .decrypt_padded_b2b_mut::<Pkcs7>(ct, &mut buf).ok()?,
                24 => Aes192CbcDec::new_from_slices(key, &iv).ok()?
                    .decrypt_padded_b2b_mut::<Pkcs7>(ct, &mut buf).ok()?,
                32 => Aes256CbcDec::new_from_slices(key, &iv).ok()?
                    .decrypt_padded_b2b_mut::<Pkcs7>(ct, &mut buf).ok()?,
                _ => return None,
            };
            Some(pt.to_vec())
        }
        AlgoKind::Sm4Cbc => {
            if key.len() != 16 || ct.len() < 2 * B16 || ct.len() % B16 != 0 {
                return None;
            }
            let iv = [0u8; B16];
            let mut buf = vec![0u8; ct.len()];
            let pt = Sm4CbcDec::new_from_slices(key, &iv).ok()?
                .decrypt_padded_b2b_mut::<Pkcs7>(ct, &mut buf).ok()?;
            Some(pt.to_vec())
        }
        AlgoKind::DesCbc => {
            if key.len() != 8 || ct.len() < 2 * B8 || ct.len() % B8 != 0 {
                return None;
            }
            let iv = [0u8; B8];
            let mut buf = vec![0u8; ct.len()];
            let pt = DesCbcDec::new_from_slices(key, &iv).ok()?
                .decrypt_padded_b2b_mut::<Pkcs7>(ct, &mut buf).ok()?;
            Some(pt.to_vec())
        }
        AlgoKind::TdesCbc => {
            if key.len() != 24 || ct.len() < 2 * B8 || ct.len() % B8 != 0 {
                return None;
            }
            let iv = [0u8; B8];
            let mut buf = vec![0u8; ct.len()];
            let pt = TdesCbcDec::new_from_slices(key, &iv).ok()?
                .decrypt_padded_b2b_mut::<Pkcs7>(ct, &mut buf).ok()?;
            Some(pt.to_vec())
        }
        _ => None,
    }
}

/// 一次解密尝试: 明文 + 对应的 IV (None = 未知) + 判据要跳过的不可信前缀字节数。
pub struct DecryptAttempt {
    pub plain: Vec<u8>,
    pub iv_hex: Option<String>,
    /// 无前置 IV 约定下首块是乱码, 判据/预览要跳过这么多字节。
    pub judge_skip: usize,
}

/// 对 (kind, key, ct) 枚举所有「IV 约定」下的解密结果。
///
/// CBC 系: 同时给出 ① 前置 IV (密文前一块当 IV) 和 ② 无前置 IV (整段密文, 零 IV,
/// 首块未知) 两种解读, 交给判据各自筛。真实报文通常只有一种约定能通过判据,
/// 因此不会重复刷屏 (见 scan 循环里 strong/weak 的取舍)。其它算法走原 `try_decrypt` 单路。
pub fn decrypt_attempts(kind: AlgoKind, key: &[u8], ct: &[u8]) -> Vec<DecryptAttempt> {
    let bs = match kind {
        AlgoKind::AesCbc | AlgoKind::Sm4Cbc => 16,
        AlgoKind::DesCbc | AlgoKind::TdesCbc => 8,
        _ => 0,
    };
    if bs == 0 {
        // 非 CBC: 沿用既有单路约定 (IV 取密文头部)
        return match try_decrypt(kind, key, ct) {
            Some(pt) => vec![DecryptAttempt {
                plain: pt,
                iv_hex: extract_iv(kind, ct).map(hex::encode),
                judge_skip: 0,
            }],
            None => vec![],
        };
    }
    let mut out = Vec::with_capacity(2);
    // 约定 ①: 前置 IV
    if let Some(pt) = try_decrypt(kind, key, ct) {
        out.push(DecryptAttempt {
            plain: pt,
            iv_hex: Some(hex::encode(&ct[..bs])),
            judge_skip: 0,
        });
    }
    // 约定 ②: 无前置 IV / 零 IV, 首块未知
    if let Some(pt) = try_decrypt_cbc_zero_iv(kind, key, ct) {
        out.push(DecryptAttempt {
            plain: pt,
            iv_hex: None,
            judge_skip: bs,
        });
    }
    out
}

/// 判断一次解密尝试是否给出「完整」明文: 去掉不可信前缀 (judge_skip) 后, 文本以
/// `{` 或 `[` 开头 —— 即真实首块就在结果里 (前置 IV 约定正确)。不完整说明真首块被
/// 当成了 IV, 需要无前置 IV 约定 + IV 反查来补回。
fn attempt_is_complete(att: &DecryptAttempt) -> bool {
    if att.plain.len() <= att.judge_skip {
        return false;
    }
    let s = String::from_utf8_lossy(&att.plain[att.judge_skip..]);
    let t = s.trim_start();
    t.starts_with('{') || t.starts_with('[')
}

/// CBC 系算法的块大小 (字节);非 CBC 返回 0。
fn cbc_block_size(kind: AlgoKind) -> usize {
    match kind {
        AlgoKind::AesCbc | AlgoKind::Sm4Cbc => 16,
        AlgoKind::DesCbc | AlgoKind::TdesCbc => 8,
        _ => 0,
    }
}

/// 对 CBC 系算法做单块 ECB 解密 (即裸 `Decrypt(K, block)`, 不异或、不去填充)。
fn ecb_decrypt_block(kind: AlgoKind, key: &[u8], block: &[u8]) -> Option<Vec<u8>> {
    use cipher::generic_array::GenericArray;
    use cipher::{BlockDecrypt, KeyInit};
    let bs = cbc_block_size(kind);
    if bs == 0 || block.len() < bs {
        return None;
    }
    // 16 字节块 (AES / SM4)
    if bs == 16 {
        let mut b = GenericArray::clone_from_slice(&block[..16]);
        match kind {
            AlgoKind::AesCbc => match key.len() {
                16 => aes::Aes128::new_from_slice(key).ok()?.decrypt_block(&mut b),
                24 => aes::Aes192::new_from_slice(key).ok()?.decrypt_block(&mut b),
                32 => aes::Aes256::new_from_slice(key).ok()?.decrypt_block(&mut b),
                _ => return None,
            },
            AlgoKind::Sm4Cbc if key.len() == 16 => {
                sm4::Sm4::new_from_slice(key).ok()?.decrypt_block(&mut b)
            }
            _ => return None,
        }
        return Some(b.to_vec());
    }
    // 8 字节块 (DES / 3DES)
    let mut b = GenericArray::clone_from_slice(&block[..8]);
    match kind {
        AlgoKind::DesCbc if key.len() == 8 => {
            des::Des::new_from_slice(key).ok()?.decrypt_block(&mut b)
        }
        AlgoKind::TdesCbc if key.len() == 24 => {
            des::TdesEde3::new_from_slice(key).ok()?.decrypt_block(&mut b)
        }
        _ => return None,
    }
    Some(b.to_vec())
}

/// 已知 key + 无前置 IV 的密文后, 尝试恢复真实 IV, 从而补出乱码的首块明文。
///
/// 原理: `D = Decrypt(K, C₀) = P₀ XOR IV`, 故 `P₀ = D XOR IV`。固定/写死的 IV 几乎
/// 总能在内存 dump 里找到, 所以在 dump 里找 16(或 8) 字节窗口 W, 使 `D XOR W` 是合法
/// JSON 头部 (`{"…` 或 `[…`, 且整块是文本) —— 命中即 IV = W。先试几个常见启发式 IV
/// (全 FF / key 前缀), 再全 dump 扫描。
///
/// `body_plain` 是约定②解出的明文 (首块乱码, 其余正确)。返回 (iv, 完整明文)。
pub fn recover_cbc_iv(
    kind: AlgoKind,
    key: &[u8],
    ct: &[u8],
    body_plain: &[u8],
    sources: &[Arc<Vec<u8>>],
    stop: &AtomicBool,
) -> Option<(Vec<u8>, Vec<u8>)> {
    let bs = cbc_block_size(kind);
    if bs == 0 || ct.len() < bs || body_plain.len() < bs {
        return None;
    }
    let d = ecb_decrypt_block(kind, key, &ct[..bs])?;
    let tail = &body_plain[bs..]; // 首块之后的明文, 已正确

    // 候选 IV 验证 (排除假阳性的关键, 两道一起卡):
    //  ① 恢复出的首块 P₀ 必须是「干净的 JSON 对象开头」: `{"` + 仅 key 安全字符。
    //     光是 JSON 良构不够 —— `{"<14 个随机可打印字节>` 也能当成一个怪 key, 4.6GB
    //     里这种能凑出上万个。限定 P₀ 全是 [字母数字 _-.":,{}[] 空格] 后, 假阳性 ~0。
    //  ② 拼上真实尾部后, 整体必须是良构 JSON。
    let clean_obj_head = |p0: &[u8]| -> bool {
        p0.first() == Some(&b'{')
            && p0.get(1) == Some(&b'"')
            && p0
                .iter()
                .all(|&c| c.is_ascii_alphanumeric() || b"_-.\"':,{}[] ".contains(&c))
    };
    let try_iv = |iv: &[u8]| -> Option<(Vec<u8>, Vec<u8>)> {
        let p0: Vec<u8> = d.iter().zip(iv.iter()).map(|(a, b)| a ^ b).collect();
        if !clean_obj_head(&p0) {
            return None;
        }
        let mut full = p0;
        full.extend_from_slice(tail);
        if json_well_formed(&String::from_utf8_lossy(&full)) {
            Some((iv.to_vec(), full))
        } else {
            None
        }
    };

    // 1) 常见启发式 IV
    let mut heur: Vec<Vec<u8>> = vec![vec![0x00u8; bs], vec![0xFFu8; bs]];
    if key.len() >= bs {
        heur.push(key[..bs].to_vec());
    }
    if key.len() >= 2 * bs {
        heur.push(key[bs..2 * bs].to_vec());
    }
    for iv in &heur {
        if let Some(r) = try_iv(iv) {
            return Some(r);
        }
    }

    // 2) 全 dump 扫描 (IV 通常是写死常量, 在内存里)。
    //    热路径无分配: 先用前两字节 (P₀ 的开头 `{"` / `[`) 做廉价预筛, 命中再做 JSON 校验。
    let d0 = d[0];
    let d1 = d[1];
    for src in sources {
        let s = src.as_slice();
        if s.len() < bs {
            continue;
        }
        let mut i = 0usize;
        let last = s.len() - bs;
        while i <= last {
            if (i & 0x3F_FFFF) == 0 && stop.load(Ordering::Relaxed) {
                return None;
            }
            // P₀[0..2] = d[0..2] XOR W[0..2]; 只对以 `{"` 开头的候选做完整校验
            if d0 ^ s[i] == b'{' && d1 ^ s[i + 1] == b'"' {
                if let Some(r) = try_iv(&s[i..i + bs]) {
                    return Some(r);
                }
            }
            i += 1;
        }
    }
    None
}

/// 轻量 JSON 良构性校验 (不引入依赖)。整串必须恰好是一个合法 JSON 值 (对象/数组/
/// 字符串/数字/true/false/null), 前后允许空白。用于 IV 反查时排除「尾部像 JSON 但
/// 首块是乱码」的假阳性。字符串值里的多字节 UTF-8 照单全收, 控制字符视为非法。
fn json_well_formed(s: &str) -> bool {
    let mut p = JsonParser { b: s.as_bytes(), i: 0 };
    p.skip_ws();
    if !p.value() {
        return false;
    }
    p.skip_ws();
    p.i == p.b.len()
}

struct JsonParser<'a> {
    b: &'a [u8],
    i: usize,
}

impl JsonParser<'_> {
    fn skip_ws(&mut self) {
        while self.i < self.b.len() && matches!(self.b[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }
    fn value(&mut self) -> bool {
        match self.b.get(self.i) {
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b'"') => self.string(),
            Some(b't') => self.lit(b"true"),
            Some(b'f') => self.lit(b"false"),
            Some(b'n') => self.lit(b"null"),
            Some(b'-') | Some(b'0'..=b'9') => self.number(),
            _ => false,
        }
    }
    fn lit(&mut self, kw: &[u8]) -> bool {
        if self.b[self.i..].starts_with(kw) {
            self.i += kw.len();
            true
        } else {
            false
        }
    }
    fn string(&mut self) -> bool {
        self.i += 1; // 跳过开引号
        while let Some(&c) = self.b.get(self.i) {
            match c {
                b'"' => {
                    self.i += 1;
                    return true;
                }
                b'\\' => {
                    self.i += 1;
                    if self.i >= self.b.len() {
                        return false;
                    }
                    self.i += 1; // 接受任意转义 (含 \uXXXX 不细究)
                }
                0x00..=0x1f => return false, // JSON 字符串里控制字符非法
                _ => self.i += 1,
            }
        }
        false
    }
    fn number(&mut self) -> bool {
        let start = self.i;
        if self.b.get(self.i) == Some(&b'-') {
            self.i += 1;
        }
        while self.i < self.b.len()
            && matches!(self.b[self.i], b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-')
        {
            self.i += 1;
        }
        self.i > start
    }
    fn object(&mut self) -> bool {
        self.i += 1; // {
        self.skip_ws();
        if self.b.get(self.i) == Some(&b'}') {
            self.i += 1;
            return true;
        }
        loop {
            self.skip_ws();
            if self.b.get(self.i) != Some(&b'"') || !self.string() {
                return false;
            }
            self.skip_ws();
            if self.b.get(self.i) != Some(&b':') {
                return false;
            }
            self.i += 1;
            self.skip_ws();
            if !self.value() {
                return false;
            }
            self.skip_ws();
            match self.b.get(self.i) {
                Some(b',') => self.i += 1,
                Some(b'}') => {
                    self.i += 1;
                    return true;
                }
                _ => return false,
            }
        }
    }
    fn array(&mut self) -> bool {
        self.i += 1; // [
        self.skip_ws();
        if self.b.get(self.i) == Some(&b']') {
            self.i += 1;
            return true;
        }
        loop {
            self.skip_ws();
            if !self.value() {
                return false;
            }
            self.skip_ws();
            match self.b.get(self.i) {
                Some(b',') => self.i += 1,
                Some(b']') => {
                    self.i += 1;
                    return true;
                }
                _ => return false,
            }
        }
    }
}

// ─── 哈希 / HMAC 指纹匹配 ─────────────────────────────────────────

/// 比较 hash(key) 是否与期望前缀匹配 (允许 expected 长度等于 hash 长度,或被截断)
fn digest_match<H: Digest>(key: &[u8], expected: &[u8]) -> Option<Vec<u8>> {
    let computed = H::digest(key).to_vec();
    let n = computed.len().min(expected.len());
    if n == 0 {
        return None;
    }
    if computed[..n] == expected[..n] && expected.len() <= computed.len() {
        Some(computed)
    } else {
        None
    }
}

pub fn try_hash(kind: AlgoKind, key: &[u8], expected: &[u8]) -> Option<Vec<u8>> {
    match kind {
        AlgoKind::Md5 => digest_match::<md5::Md5>(key, expected),
        AlgoKind::Sha1 => digest_match::<sha1::Sha1>(key, expected),
        AlgoKind::Sha256 => digest_match::<sha2::Sha256>(key, expected),
        AlgoKind::Sha512 => digest_match::<sha2::Sha512>(key, expected),
        AlgoKind::Sm3 => digest_match::<sm3::Sm3>(key, expected),
        AlgoKind::Ripemd160 => digest_match::<ripemd::Ripemd160>(key, expected),
        _ => None,
    }
}

fn hmac_match<H>(key: &[u8], msg: &[u8], expected: &[u8]) -> Option<Vec<u8>>
where
    H: digest::Mac + KeyInit,
{
    let mut m = <H as KeyInit>::new_from_slice(key).ok()?;
    m.update(msg);
    let tag = m.finalize().into_bytes().to_vec();
    let n = tag.len().min(expected.len());
    if n == 0 {
        return None;
    }
    if tag[..n] == expected[..n] && expected.len() <= tag.len() {
        Some(tag)
    } else {
        None
    }
}

pub fn try_hmac(kind: AlgoKind, key: &[u8], msg: &[u8], expected: &[u8]) -> Option<Vec<u8>> {
    use hmac::Hmac;
    match kind {
        AlgoKind::HmacMd5 => hmac_match::<Hmac<md5::Md5>>(key, msg, expected),
        AlgoKind::HmacSha1 => hmac_match::<Hmac<sha1::Sha1>>(key, msg, expected),
        AlgoKind::HmacSha224 => hmac_match::<Hmac<sha2::Sha224>>(key, msg, expected),
        AlgoKind::HmacSha256 => hmac_match::<Hmac<sha2::Sha256>>(key, msg, expected),
        AlgoKind::HmacSha384 => hmac_match::<Hmac<sha2::Sha384>>(key, msg, expected),
        AlgoKind::HmacSha512 => hmac_match::<Hmac<sha2::Sha512>>(key, msg, expected),
        AlgoKind::HmacSha3 => hmac_match::<Hmac<sha3::Sha3_256>>(key, msg, expected),
        AlgoKind::HmacSm3 => hmac_match::<Hmac<sm3::Sm3>>(key, msg, expected),
        AlgoKind::HmacRipemd => hmac_match::<Hmac<ripemd::Ripemd160>>(key, msg, expected),
        _ => None,
    }
}

// ─── 命中判据 ─────────────────────────────────────────────────────

pub struct HitMeta {
    pub reason: &'static str,
    /// 强信号 (关键字命中 / 完整 JSON / 高 ASCII 可读)。弱信号 (仅 JSON 尾部) 用于
    /// 首块未知的无 IV 约定。scan 循环优先报强信号, 避免同一 key 两种约定都刷屏。
    pub strong: bool,
}

/// 看起来像「JSON 对象/数组的尾部」: 以 } 或 ] 收尾, 且含 JSON 字段分隔符。
/// 用于无前置 IV 约定 (首 16 字节是乱码, 拿不到开头的 `{`) 时识别命中。
fn looks_json_tail(s: &str) -> bool {
    let t = s.trim();
    (t.ends_with('}') || t.ends_with(']'))
        && (t.contains("\":\"")
            || t.contains("\",\"")
            || t.contains("\":[")
            || t.contains("\":{")
            || t.contains("\":"))
}

/// 对一次解密产物判断"是否值得作为候选输出给用户"。
///
/// 设计原则: 宁可漏报, 不要刷屏的假阳性。
///  * 用户给了 plain_contains → 严格要求子串命中, 不再 fallback 到 ratio 启发式
///  * 短输出 (< 24 字节) 不走 ratio 启发式: 16 字节随机 XOR 太容易碰巧像 ASCII
///  * ASCII 启发式要求 ratio ≥ 0.95 且字母占比 ≥ 0.25 (避免纯标点/数字假命中)
///  * 结构判据用「文本占比」(含合法 UTF-8 多字节), 中日韩 JSON 不会被 ratio 卡掉
pub fn judge_hit(plain: &[u8], plain_contains: &str) -> Option<HitMeta> {
    judge_hit_inner(plain, plain_contains, 0)
}

/// `skip`: 跳过开头不可信的字节 (无前置 IV 约定下首块是乱码)。skip > 0 时只能
/// 看 JSON 尾部特征, 判定为弱信号 (`strong = false`)。
pub fn judge_hit_inner(plain: &[u8], plain_contains: &str, skip: usize) -> Option<HitMeta> {
    if plain.len() <= skip {
        return None;
    }
    let body = &plain[skip..];
    let body_str = String::from_utf8_lossy(body);
    let kw = plain_contains.trim();

    // 1. 用户给了关键字: 唯一权威信号; 在可信区间 (跳过首块) 内搜索
    if !kw.is_empty() {
        if body_str.contains(kw) {
            return Some(HitMeta { reason: "关键字命中", strong: true });
        }
        return None;
    }

    // 2. 没有关键字: 走结构 / ratio 启发式
    let s = body_str.trim();
    let txt = text_ratio(body); // 含合法 UTF-8 多字节, 兼容 CJK
    if skip == 0 {
        // 首块可信: 要求完整 JSON 包裹
        let json_full = (s.starts_with('{') && s.ends_with('}'))
            || (s.starts_with('[') && s.ends_with(']'));
        if json_full && txt >= 0.9 && body.len() >= 12 {
            return Some(HitMeta { reason: "JSON 结构", strong: true });
        }
    } else {
        // 首块未知: 只能看 JSON 尾部特征
        if txt >= 0.85 && body.len() >= 12 && looks_json_tail(s) {
            return Some(HitMeta { reason: "JSON 结构(首块未知)", strong: false });
        }
    }

    // 短输出 (< 24 字节) 无足够上下文判断, 不走 ratio
    if body.len() < 24 {
        return None;
    }

    // 纯 ASCII 可读 (这里仍用严格可打印 ASCII 计数, 不放进 UTF-8 文本)
    let printable = body
        .iter()
        .filter(|&&c| c == b'\n' || c == b'\r' || c == b'\t' || (0x20..=0x7e).contains(&c))
        .count();
    let ratio = printable as f32 / body.len() as f32;
    if ratio >= 0.95 {
        let alpha = body
            .iter()
            .filter(|c| c.is_ascii_alphabetic())
            .count() as f32
            / body.len() as f32;
        if alpha >= 0.25 {
            return Some(HitMeta {
                reason: if skip == 0 { "ASCII 可读" } else { "ASCII 可读(首块未知)" },
                strong: skip == 0,
            });
        }
    }

    None
}

// ─── 后台引擎 ─────────────────────────────────────────────────────

#[derive(Clone)]
pub struct EngineConfig {
    pub algo_ids: Vec<String>,
    pub key_lens: Vec<usize>,
    pub ascii_only: bool,
    pub dedup: bool,
    pub key_encode: bool,
    pub deep_search: bool,
    /// 解密判定时的明文关键字 (e.g. "token=")
    pub plain_contains: String,
    /// 哈希反查 / HMAC message 用的完整已知明文
    pub known_plaintext: String,
    pub threads: usize,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum MsgLvl {
    Info,
    Ok,
    Warn,
    Err,
}

pub enum EngineMsg {
    Log {
        lvl: MsgLvl,
        msg: String,
        accent: bool,
    },
    Progress {
        pct: f32,
        current: String,
    },
    Hit {
        algo: String,
        key_hex: String,
        /// 对 CBC/CFB/CTR/GCM/ChaCha20 等带 IV 的对称算法, 从 ct 前缀提取的 IV 的 hex。
        iv_hex: Option<String>,
        plain_preview: Option<String>,
        /// 完整明文字节, 给"导出原文"用。preview 是给 UI 卡片展示用的截断版本。
        plain_full: Option<Vec<u8>>,
        reason: String,
        elapsed_ms: u64,
    },
    Done {
        hits: usize,
        candidates: usize,
        elapsed_ms: u64,
        stopped: bool,
    },
}

pub struct EngineHandle {
    pub rx: Receiver<EngineMsg>,
    pub stop: Arc<AtomicBool>,
}

pub fn spawn(cfg: EngineConfig, files: Vec<Arc<Vec<u8>>>, ct: Vec<u8>) -> EngineHandle {
    let (tx, rx) = mpsc::channel();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_w = stop.clone();

    thread::spawn(move || {
        run_job(cfg, files, ct, tx, stop_w);
    });

    EngineHandle { rx, stop }
}

fn send(tx: &Sender<EngineMsg>, m: EngineMsg) {
    let _ = tx.send(m);
}

fn log(tx: &Sender<EngineMsg>, lvl: MsgLvl, msg: impl Into<String>, accent: bool) {
    let _ = tx.send(EngineMsg::Log {
        lvl,
        msg: msg.into(),
        accent,
    });
}

fn run_job(
    cfg: EngineConfig,
    files: Vec<Arc<Vec<u8>>>,
    ct: Vec<u8>,
    tx: Sender<EngineMsg>,
    stop: Arc<AtomicBool>,
) {
    let t0 = Instant::now();

    if ct.is_empty() {
        log(&tx, MsgLvl::Err, "密文为空,任务终止", false);
        send(&tx, EngineMsg::Done {
            hits: 0,
            candidates: 0,
            elapsed_ms: 0,
            stopped: false,
        });
        return;
    }
    log(&tx, MsgLvl::Info, format!("密文 {} 字节", ct.len()), false);

    // 场景识别: 密文长度与常见哈希输出对齐时,给出提示
    let hash_hint = match ct.len() {
        16 => Some("MD5"),
        20 => Some("SHA-1 / RIPEMD-160"),
        28 => Some("SHA-224"),
        32 => Some("SHA-256 / SM3"),
        48 => Some("SHA-384"),
        64 => Some("SHA-512"),
        _ => None,
    };
    let known_plaintext_empty = cfg.known_plaintext.trim().is_empty();
    let plain_contains_empty = cfg.plain_contains.trim().is_empty();

    if let Some(h) = hash_hint {
        if known_plaintext_empty {
            log(
                &tx,
                MsgLvl::Warn,
                format!(
                    "密文长度与 {} 输出对齐, 但 '已知明文' 字段为空 → 无法做哈希反查",
                    h
                ),
                true,
            );
        } else {
            log(
                &tx,
                MsgLvl::Info,
                format!("密文长度与 {} 输出对齐, 将对哈希算法做单点反查", h),
                false,
            );
        }
    }
    if plain_contains_empty && known_plaintext_empty && ct.len() <= 32 {
        log(
            &tx,
            MsgLvl::Warn,
            "未填写 '已知明文' 也未填写 '原文包含'。短密文场景下命中判定全靠这两个字段:\
             已知明文 → 反查哈希; 原文包含 → 解密结果关键字过滤",
            false,
        );
    }

    if files.is_empty() {
        log(
            &tx,
            MsgLvl::Warn,
            "未提供任何 dump 文件,引擎将无候选 KEY 可用",
            false,
        );
    } else {
        let total_bytes: usize = files.iter().map(|f| f.len()).sum();
        log(
            &tx,
            MsgLvl::Info,
            format!("加载 {} 个数据源,共 {} 字节", files.len(), total_bytes),
            false,
        );
    }

    // 解析所选算法
    let mut specs: Vec<&'static AlgoSpec> = Vec::new();
    for id in &cfg.algo_ids {
        match lookup_spec(id) {
            Some(s) => specs.push(s),
            None => log(&tx, MsgLvl::Warn, format!("未知算法 id: {id}"), false),
        }
    }
    if specs.is_empty() {
        log(&tx, MsgLvl::Err, "未选择任何算法,任务终止", false);
        send(&tx, EngineMsg::Done {
            hits: 0,
            candidates: 0,
            elapsed_ms: t0.elapsed().as_millis() as u64,
            stopped: false,
        });
        return;
    }

    // 流式哈希反查: 触发条件 = 密文长度像哈希 + 没填已知明文 + 有 dump 数据 + 有启用的哈希算法
    let do_streaming_hash = hash_hint.is_some()
        && known_plaintext_empty
        && !files.is_empty()
        && specs.iter().any(|s| s.kind.is_hash());
    let mut streaming_hash_done = false;

    // 注意: 不再 extract_candidates。streaming 路径直接从 files 扫描, 无 5M 候选上限。
    // 旧的 candidates Vec 完全是冗余的: 1) streaming 覆盖所有 dump 数据 2) HMAC 在没有 known_plaintext 时被跳过 3) 哈希走 streaming 或 known_plaintext 单点

    if stop.load(Ordering::Relaxed) {
        send(&tx, EngineMsg::Done {
            hits: 0,
            candidates: 0,
            elapsed_ms: t0.elapsed().as_millis() as u64,
            stopped: true,
        });
        return;
    }

    // 设置 rayon 线程池
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(cfg.threads.max(1))
        .build();
    let pool = match pool {
        Ok(p) => p,
        Err(e) => {
            log(&tx, MsgLvl::Err, format!("线程池创建失败: {e}"), false);
            send(&tx, EngineMsg::Done {
                hits: 0,
                candidates: 0,
                elapsed_ms: t0.elapsed().as_millis() as u64,
                stopped: false,
            });
            return;
        }
    };
    log(
        &tx,
        MsgLvl::Ok,
        format!("线程池就绪 ({})", cfg.threads.max(1)),
        false,
    );

    let total = specs.len();
    let total_hits = Arc::new(AtomicUsize::new(0));
    let scanned = Arc::new(AtomicUsize::new(0));

    let known_plaintext: Vec<u8> = cfg.known_plaintext.trim().as_bytes().to_vec();

    // 阶段 0: 流式哈希反查 (一遍扫完 dump, 比 per-algo iterate 快得多, 也无上限)
    if do_streaming_hash {
        let hash_pairs: Vec<(AlgoKind, &'static str)> = specs
            .iter()
            .filter(|s| s.kind.is_hash())
            .map(|s| (s.kind, s.name))
            .collect();
        log(
            &tx,
            MsgLvl::Info,
            format!(
                "启用流式哈希反查: 一次扫描覆盖 {} 个哈希算法, 无字符串数量上限",
                hash_pairs.len()
            ),
            true,
        );
        let h = streaming_hash_match(
            &files,
            &ct,
            &hash_pairs,
            STRING_MIN_LEN,
            HASH_REVERSE_MAX_LEN,
            &stop,
            &tx,
            t0,
        );
        total_hits.fetch_add(h, Ordering::Relaxed);
        streaming_hash_done = true;
    }

    // 阶段 1: 流式对称 + HMAC 扫描 (覆盖整个 dump, 无 5M 候选上限)
    // 先按密文长度过滤掉不兼容的对称算法 (e.g. AES-ECB 需 ct%16==0)
    let sym_all: Vec<&'static AlgoSpec> = specs
        .iter()
        .filter(|s| !s.kind.is_hash() && !s.kind.is_hmac())
        .copied()
        .collect();
    let sym_specs: Vec<&'static AlgoSpec> = sym_all
        .iter()
        .copied()
        .filter(|s| is_ct_compatible(s.kind, ct.len()))
        .collect();
    if sym_specs.len() < sym_all.len() {
        let dropped: Vec<&'static str> = sym_all
            .iter()
            .filter(|s| !is_ct_compatible(s.kind, ct.len()))
            .map(|s| s.name)
            .collect();
        log(
            &tx,
            MsgLvl::Info,
            format!(
                "按密文长度 ({} 字节) 预过滤: 对称算法 {} → {} 个 (跳过: {})",
                ct.len(),
                sym_all.len(),
                sym_specs.len(),
                dropped.join(", ")
            ),
            false,
        );
    }
    let hmac_specs: Vec<&'static AlgoSpec> = specs
        .iter()
        .filter(|s| s.kind.is_hmac())
        .copied()
        .collect();
    let do_streaming_sym = !files.is_empty()
        && ct.len() >= 8
        && (!sym_specs.is_empty()
            || (!hmac_specs.is_empty() && !known_plaintext.is_empty()));
    let mut streaming_sym_done = false;
    if do_streaming_sym && !stop.load(Ordering::Relaxed) {
        log(
            &tx,
            MsgLvl::Info,
            format!(
                "启用流式对称+HMAC 扫描: {} 个对称算法 + {} 个 HMAC 算法, 一次扫描覆盖整个 dump, 无候选 KEY 上限",
                sym_specs.len(),
                if known_plaintext.is_empty() { 0 } else { hmac_specs.len() }
            ),
            true,
        );
        let h = streaming_dump_match(
            &files,
            &ct,
            &sym_specs,
            &hmac_specs,
            &cfg.key_lens,
            &cfg.plain_contains,
            &known_plaintext,
            cfg.deep_search,
            cfg.ascii_only,
            &stop,
            &tx,
            t0,
        );
        total_hits.fetch_add(h, Ordering::Relaxed);
        streaming_sym_done = true;
    }

    pool.install(|| {
        for (idx, spec) in specs.iter().enumerate() {
            if stop.load(Ordering::Relaxed) {
                log(&tx, MsgLvl::Warn, "收到停止信号", true);
                break;
            }

            let kind = spec.kind;

            // 流式哈希反查已经覆盖了所有哈希算法, 这里跳过 (不要覆盖流式上报的进度)
            if streaming_hash_done && kind.is_hash() {
                continue;
            }

            // 流式对称+HMAC 扫描已经覆盖了所有对称算法 (+ HMAC 当 known_plaintext 非空时)
            if streaming_sym_done && !kind.is_hash() {
                if !kind.is_hmac() || !known_plaintext.is_empty() {
                    continue;
                }
            }

            // HMAC 没有已知明文就没法反查 (没 message 没法算 HMAC), 跳过
            if kind.is_hmac() && known_plaintext.is_empty() {
                log(
                    &tx,
                    MsgLvl::Warn,
                    format!("→ {} 跳过: HMAC 反查需要 '已知明文' 字段", spec.name),
                    false,
                );
                continue;
            }

            // 到这里只剩一种情况: 哈希算法 + 已知明文 (streaming_hash 不跑这条路, 因为单点更快)
            if kind.is_hash() && !known_plaintext.is_empty() {
                if try_hash(kind, &known_plaintext, &ct).is_some() {
                    total_hits.fetch_add(1, Ordering::Relaxed);
                    log(
                        &tx,
                        MsgLvl::Ok,
                        format!("命中 {} · {}(已知明文) == 密文", spec.name, spec.name),
                        true,
                    );
                    send(&tx, EngineMsg::Hit {
                        algo: spec.name.to_string(),
                        key_hex: "— (无 key, 哈希反查)".to_string(),
                        iv_hex: None,
                        plain_preview: Some(make_preview(&known_plaintext)),
                        plain_full: Some(known_plaintext.clone()),
                        reason: "已知明文 hash 反查".to_string(),
                        elapsed_ms: t0.elapsed().as_millis() as u64,
                    });
                }
            }

            let pct = ((idx + 1) as f32 / total as f32) * 100.0;
            send(&tx, EngineMsg::Progress {
                pct,
                current: spec.name.to_string(),
            });
        }
    });

    let hits = total_hits.load(Ordering::Relaxed);
    let stopped = stop.load(Ordering::Relaxed);
    log(
        &tx,
        if hits > 0 { MsgLvl::Ok } else { MsgLvl::Info },
        format!(
            "推算{} · 命中 {} 项,耗时 {}ms",
            if stopped { "已停止" } else { "完成" },
            hits,
            t0.elapsed().as_millis()
        ),
        true,
    );

    // 0 命中: 给针对性建议
    if hits == 0 && !stopped {
        if let Some(h) = hash_hint {
            if known_plaintext_empty {
                if streaming_hash_done {
                    log(
                        &tx,
                        MsgLvl::Warn,
                        format!(
                            "流式 {} 反查扫完整个 dump 均未命中。可能原因:\
                             (1) 明文不在该 dump 里; \
                             (2) 明文含 NUL / 0x80-0xff 等切分字节 (常见: UTF-8 中文 / 二进制头);\
                             (3) 明文是更长文本段的子串, 整段被当成一条 hash 候选;\
                             (4) dump 里的明文已被覆盖 / 释放。\
                             可直接在 '已知明文' 字段贴入候选明文验证",
                            h
                        ),
                        true,
                    );
                } else {
                    log(
                        &tx,
                        MsgLvl::Warn,
                        format!(
                            "密文长度匹配 {} 输出但无 dump 数据。请: 加载 dump 文件 (自动字符串扫描反查) 或在 '已知明文' 字段填入完整原文",
                            h
                        ),
                        true,
                    );
                }
            }
        } else if plain_contains_empty && ct.len() < 24 {
            log(
                &tx,
                MsgLvl::Warn,
                "密文较短且未提供任何明文信息。请填入 '已知明文' (反查哈希) 或 '原文包含' (解密关键字)",
                true,
            );
        }
    }
    send(&tx, EngineMsg::Done {
        hits,
        candidates: scanned.load(Ordering::Relaxed),
        elapsed_ms: t0.elapsed().as_millis() as u64,
        stopped,
    });
}

fn hex_short(b: &[u8]) -> String {
    let s = hex::encode_upper(b);
    if s.len() > 24 {
        format!("{}…({}B)", &s[..24], b.len())
    } else {
        s
    }
}

fn format_key_hex(b: &[u8]) -> String {
    hex::encode(b)
}

/// 命中卡片显示用的算法全名: AES 系列附带 key 位长 (128/192/256), 其他原样。
fn algo_display_name(kind: AlgoKind, key_len: usize) -> String {
    let base = ALGO_SPECS
        .iter()
        .find(|s| s.kind == kind)
        .map(|s| s.name)
        .unwrap_or("?");
    if base.starts_with("AES-") {
        format!("AES-{}-{}", key_len * 8, &base[4..])
    } else {
        base.to_string()
    }
}

/// 对带 IV / nonce 的对称算法, 从 ct 前缀中切出 IV; 其余返回 None。
fn extract_iv(kind: AlgoKind, ct: &[u8]) -> Option<Vec<u8>> {
    let n = match kind {
        AlgoKind::AesCbc | AlgoKind::AesCfb | AlgoKind::AesCtr => 16,
        AlgoKind::AesGcm | AlgoKind::ChaCha20 => 12,
        AlgoKind::Sm4Cbc | AlgoKind::Sm4Cfb => 16,
        AlgoKind::DesCbc | AlgoKind::TdesCbc => 8,
        _ => return None,
    };
    if ct.len() >= n {
        Some(ct[..n].to_vec())
    } else {
        None
    }
}

fn make_preview(plain: &[u8]) -> String {
    let max = 220.min(plain.len());
    let slice = &plain[..max];
    let mut s = String::from_utf8_lossy(slice).into_owned();
    if plain.len() > max {
        s.push_str(&format!("…(+{}B)", plain.len() - max));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipher::BlockEncryptMut;

    type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

    /// 端到端: 构造已知 key/iv 加密一段 JSON, 把 key 埋进 dump 字节流,
    /// 然后让引擎完整跑一遍, 看是否能命中。
    #[test]
    fn end_to_end_aes256_cbc_hit() {
        let key = b"correct horse battery staple!!!!"; // 32 字节
        assert_eq!(key.len(), 32);
        let iv = [0x42u8; 16];
        let plaintext = br#"{"uid":"u_1042","ok":true,"token":"abc"}"#;

        // 用 RustCrypto 加密一遍, 拼成 IV || ct
        let mut buf = vec![0u8; plaintext.len() + 16];
        let ct_len = Aes256CbcEnc::new_from_slices(key, &iv)
            .unwrap()
            .encrypt_padded_b2b_mut::<Pkcs7>(plaintext, &mut buf)
            .unwrap()
            .len();
        let mut ct = iv.to_vec();
        ct.extend_from_slice(&buf[..ct_len]);

        // 把 key 埋进一段噪声里
        let mut dump = vec![0u8; 4096];
        dump[1234..1234 + 32].copy_from_slice(key);

        // 直接走 try_decrypt 验证
        let pt = try_decrypt(AlgoKind::AesCbc, key, &ct).expect("decrypt");
        assert_eq!(pt.as_slice(), plaintext.as_slice());

        // 走 extract + judge_hit 验证整套判据
        let cands = extract_candidates(
            &[Arc::new(dump)],
            ExtractOpts {
                lens: &[32],
                ascii_only: false,
                dedup: true,
                key_encode: false,
                deep_search: true,
                max_candidates: 1_000_000,
                stop: None,
                tx: None,
            },
        );
        assert!(cands.iter().any(|c| c.as_slice() == key));

        let mut hit_count = 0;
        for k in &cands {
            if k.len() != 32 {
                continue;
            }
            if let Some(p) = try_decrypt(AlgoKind::AesCbc, k, &ct) {
                if judge_hit(&p, "").is_some() {
                    hit_count += 1;
                }
            }
        }
        assert!(hit_count >= 1, "应至少命中 1 次 (含正确 key)");
    }

    /// 回归: 无前置 IV (固定/零 IV) + 含中文的 JSON 明文。
    /// 这正是「同行能解、本工具 0 命中」的场景: 整段都是密文, 真实 IV 不在密文里。
    #[test]
    fn end_to_end_aes256_cbc_no_prepended_iv_cjk() {
        let key = b"correct horse battery staple!!!!"; // 32 字节
        // 业务里常见的固定 IV (这里用零 IV); 密文里不携带 IV
        let iv = [0u8; 16];
        let plaintext =
            r#"{"id":"45273","name":"韦成遥","activity_ids":["109658240","109658876"]}"#.as_bytes();

        let mut buf = vec![0u8; plaintext.len() + 16];
        let ct_len = Aes256CbcEnc::new_from_slices(key, &iv)
            .unwrap()
            .encrypt_padded_b2b_mut::<Pkcs7>(plaintext, &mut buf)
            .unwrap()
            .len();
        let ct = buf[..ct_len].to_vec(); // 注意: 不前置 IV

        // 1) 快速首块过滤必须放行正确 key (含中文的明文块以前会被 ASCII 阈值误杀)
        assert!(
            looks_promising_sym(AlgoKind::AesCbc, key, &ct),
            "含中文的明文块不应被首块过滤误杀"
        );

        // 2) 无前置 IV 约定应解出明文 (首块 16B 未知, 其余正确)
        let attempts = decrypt_attempts(AlgoKind::AesCbc, key, &ct);
        let hit = attempts
            .iter()
            .filter_map(|a| judge_hit_inner(&a.plain, "", a.judge_skip).map(|m| (a, m)))
            .next()
            .expect("应在某个 IV 约定下命中");
        let (att, _) = hit;
        // 跳过首块后, 可信区间应是真实明文的尾部
        let body = String::from_utf8_lossy(&att.plain[att.judge_skip..]);
        assert!(body.contains("韦成遥"), "应解出中文 name 字段, 实际: {body}");
        assert!(body.trim_end().ends_with('}'));

        // 3) 给关键字时也应命中 (关键字在首块之后)
        let with_kw = decrypt_attempts(AlgoKind::AesCbc, key, &ct)
            .iter()
            .any(|a| judge_hit_inner(&a.plain, "activity_ids", a.judge_skip).is_some());
        assert!(with_kw, "关键字 activity_ids 应命中");

        // 4) IV 反查: 把真实 IV 藏进 dump, 应能恢复出完整明文 (含首块)
        let mut dump = vec![0u8; 8192];
        dump[4096..4096 + 16].copy_from_slice(&iv); // 真实 IV 写死在内存里
        let sources = [Arc::new(dump)];
        let stop = AtomicBool::new(false);
        let (rec_iv, full) =
            recover_cbc_iv(AlgoKind::AesCbc, key, &ct, &att.plain, &sources, &stop)
                .expect("应从 dump 反查到 IV");
        assert_eq!(rec_iv, iv);
        assert_eq!(full.as_slice(), plaintext, "应恢复出完整明文 (含 id 首块)");
        assert!(String::from_utf8_lossy(&full).starts_with("{\"id\":\"45273\""));
    }

    /// 回归 (截图 bug): 无前置 IV + 用户填了关键字。关键字落在首块之后, 两种约定都能
    /// 命中 —— 必须选「无前置 IV」约定 (能补回首块), 不能因关键字偏向前置 IV (会把真首块
    /// 当 IV 吃掉, IV 显示成 C₀, 原文缺 `{"id_card_number`)。
    #[test]
    fn keyword_match_prefers_no_prepended_iv() {
        let key = b"correct horse battery staple!!!!"; // 32 字节
        let iv = [0x11u8; 16]; // 非零固定 IV, 不在密文里
        let plaintext = r#"{"id_card_number":"452730198110175943","id_card_name":"韦成遥","phone_number":"15578889287"}"#.as_bytes();
        assert_eq!(&plaintext[..16], b"{\"id_card_number"); // 首块正好 16 字节

        let mut buf = vec![0u8; plaintext.len() + 16];
        let ct_len = Aes256CbcEnc::new_from_slices(key, &iv)
            .unwrap()
            .encrypt_padded_b2b_mut::<Pkcs7>(plaintext, &mut buf)
            .unwrap()
            .len();
        let ct = buf[..ct_len].to_vec(); // 不前置 IV

        // 复刻 scan 循环的选择逻辑: 关键字命中两种约定, 但应选不完整里 skip 最大的 (约定②)
        let keyword = "452730198110175943";
        let mut cands: Vec<(DecryptAttempt, HitMeta)> = decrypt_attempts(AlgoKind::AesCbc, key, &ct)
            .into_iter()
            .filter_map(|att| judge_hit_inner(&att.plain, keyword, att.judge_skip).map(|m| (att, m)))
            .collect();
        assert!(cands.len() >= 2, "前置/无前置两种约定都应命中关键字");
        cands.sort_by_key(|(att, _)| {
            if attempt_is_complete(att) {
                (0i32, att.judge_skip as i32)
            } else {
                (1i32, -(att.judge_skip as i32))
            }
        });
        let (winner, _) = &cands[0];
        assert!(
            winner.judge_skip > 0,
            "应选无前置 IV 约定 (skip>0), 而不是把首块当 IV 的前置约定"
        );
        assert!(winner.iv_hex.is_none(), "无前置 IV 约定不应谎报 IV = C₀");

        // IV 反查应补回真首块
        let mut dump = vec![0u8; 4096];
        dump[2000..2016].copy_from_slice(&iv);
        let sources = [Arc::new(dump)];
        let stop = AtomicBool::new(false);
        let (rec_iv, full) =
            recover_cbc_iv(AlgoKind::AesCbc, key, &ct, &winner.plain, &sources, &stop)
                .expect("应反查到 IV");
        assert_eq!(rec_iv, iv);
        assert_eq!(full.as_slice(), plaintext);
        assert!(String::from_utf8_lossy(&full).starts_with("{\"id_card_number\""));
    }

    #[test]
    fn json_validator_basics() {
        assert!(json_well_formed(r#"{"a":1,"b":[1,2,"x"],"c":{"d":true}}"#));
        assert!(json_well_formed(r#"{"name":"韦成遥","ids":["1","2"]}"#));
        assert!(json_well_formed("  [1, 2, 3]  "));
        // 截图里的假阳性: `[{乱码…` 接真实尾部不是合法 JSON
        assert!(!json_well_formed(r#"[{nBAJ$A2!T0":"452730","x":"y"}"#));
        assert!(!json_well_formed(r#"{"a":1"#)); // 未闭合
        assert!(!json_well_formed(r#"{"a":}"#)); // 缺值
        assert!(!json_well_formed("not json"));
    }

    /// 回归 (截图 bug): IV 反查不能把 dump 里碰巧凑出 `{"<乱码>` 的窗口当成 IV。
    /// 真 IV 不在 dump 里时, 应反查失败 (而不是返回乱码首块)。
    #[test]
    fn iv_recovery_rejects_garbage_first_block() {
        let key = b"correct horse battery staple!!!!";
        let iv = [0x11u8; 16];
        let plaintext = r#"{"id_card_number":"452730198110175943","name":"x"}"#.as_bytes();
        let mut buf = vec![0u8; plaintext.len() + 16];
        let n = Aes256CbcEnc::new_from_slices(key, &iv)
            .unwrap()
            .encrypt_padded_b2b_mut::<Pkcs7>(plaintext, &mut buf)
            .unwrap()
            .len();
        let ct = buf[..n].to_vec();
        let body = try_decrypt_cbc_zero_iv(AlgoKind::AesCbc, key, &ct).unwrap();

        // 真 IV 不在 dump 里 → 应反查失败, 不返回乱码
        let noise = [Arc::new(vec![0x5au8; 16384])];
        let stop = AtomicBool::new(false);
        assert!(
            recover_cbc_iv(AlgoKind::AesCbc, key, &ct, &body, &noise, &stop).is_none(),
            "真 IV 不在 dump 时不应返回任何 (乱码) IV"
        );

        // 真 IV 在 dump 里 → 应成功且首块正确
        let mut dump = vec![0x5au8; 16384];
        dump[9000..9016].copy_from_slice(&iv);
        let src = [Arc::new(dump)];
        let (riv, full) =
            recover_cbc_iv(AlgoKind::AesCbc, key, &ct, &body, &src, &stop).expect("应反查到真 IV");
        assert_eq!(riv, iv);
        assert_eq!(full.as_slice(), plaintext);
    }

    #[test]
    fn parse_ct_hex_and_base64() {
        assert_eq!(parse_ciphertext("DEADBEEF").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
        // "hello" -> aGVsbG8=
        assert_eq!(parse_ciphertext("aGVsbG8=").unwrap(), b"hello".to_vec());
        assert!(parse_ciphertext("").is_err());
    }

    #[test]
    fn judge_hit_keyword_trumps_ascii() {
        let p = b"random bytes \x01\x02 token=xyz \x99trailing";
        // 命中关键字
        assert!(judge_hit(p, "token=xyz").is_some());
        // 没关键字 + ASCII 率不够高 -> 不命中
        assert!(judge_hit(p, "").is_none());
    }

    #[test]
    fn hash_match_md5() {
        // md5("hello") = 5d41402abc4b2a76b9719d911017c592
        let expected = hex::decode("5d41402abc4b2a76b9719d911017c592").unwrap();
        assert!(try_hash(AlgoKind::Md5, b"hello", &expected).is_some());
        assert!(try_hash(AlgoKind::Md5, b"world", &expected).is_none());
    }

    /// 回归: 用户截图中那条 md5 反查场景应当通过已知明文单点测试命中
    #[test]
    fn known_plaintext_md5_lookup() {
        let plaintext = b"CF129stickerhcfz81B51600F7EB9864A069312D9A8A7E203BBBA9823C8CA7935585A8BBD68D5";
        let ct = hex::decode("9e2b481da98879313a01611361b7e7a6").unwrap();
        // 单点反查: hash(已知明文) == 密文
        assert!(try_hash(AlgoKind::Md5, plaintext, &ct).is_some());
        // 错的哈希算法应当不命中
        assert!(try_hash(AlgoKind::Sha1, plaintext, &ct).is_none());
    }

    /// 回归: dump 字符串扫描能找到藏在二进制内存里的 ASCII 明文,
    /// 配合 hash 反查可以做到"只给密文 + dump → 推出明文"
    #[test]
    fn string_scan_recovers_plaintext_from_dump() {
        let plaintext = b"CF129stickerhcfz81B51600F7EB9864A069312D9A8A7E203BBBA9823C8CA7935585A8BBD68D5";
        let ct = hex::decode("9e2b481da98879313a01611361b7e7a6").unwrap();

        // 构造一个含噪声 + 明文 + 噪声的"内存 dump"
        let mut dump = Vec::with_capacity(8192);
        dump.extend_from_slice(&[0x00u8; 1000]); // 二进制零段 → 隔断
        dump.extend_from_slice(&[0xff, 0xfe, 0x00, 0x01]); // 全部非可打印, 确保隔断
        dump.extend_from_slice(plaintext); // 真正的明文
        dump.push(0x00); // C 字符串结束符
        dump.extend_from_slice(b"some other ascii junk like a path /tmp/xyz");
        dump.extend_from_slice(&[0x80u8; 500]); // 更多二进制

        let strings = extract_strings(
            &[Arc::new(dump)],
            STRING_MIN_LEN,
            HASH_REVERSE_MAX_LEN,
            MAX_STRINGS,
            None,
            None,
        );
        // 应当从 dump 里抓到 plaintext 这段 ASCII 串
        assert!(strings.iter().any(|s| s.as_slice() == plaintext));

        // 在抓到的字符串里做 MD5 反查, 应命中
        let hit = strings.iter().find(|s| try_hash(AlgoKind::Md5, s, &ct).is_some());
        assert!(hit.is_some(), "应当在 dump 字符串里找到与密文匹配的明文");
        assert_eq!(hit.unwrap().as_slice(), plaintext);
    }

    /// 回归: 流式哈希反查无 MAX_STRINGS 上限, 能找到偏后位置的明文
    #[test]
    fn streaming_hash_finds_plaintext_late_in_dump() {
        use std::sync::mpsc::channel;
        use std::sync::atomic::AtomicBool;

        let plaintext = b"CF129stickerhcfz81B51600F7EB9864A069312D9A8A7E203BBBA9823C8CA7935585A8BBD68D5";
        let ct = hex::decode("9e2b481da98879313a01611361b7e7a6").unwrap();

        // 在前面塞大量噪声 ASCII 段, 模拟"明文出现在 dump 偏后位置"的场景。
        let mut dump = Vec::with_capacity(2_000_000);
        for i in 0..50_000 {
            dump.extend_from_slice(format!("noise_string_number_{:08}", i).as_bytes());
            dump.push(0x00);
        }
        // 紧接明文
        dump.extend_from_slice(plaintext);
        dump.push(0x00);

        let (tx, rx) = channel();
        let stop = AtomicBool::new(false);
        let hits = streaming_hash_match(
            &[Arc::new(dump)],
            &ct,
            &[(AlgoKind::Md5, "MD5")],
            STRING_MIN_LEN,
            HASH_REVERSE_MAX_LEN,
            &stop,
            &tx,
            Instant::now(),
        );
        drop(tx);
        // 应该至少命中 1 次
        assert!(hits >= 1, "流式扫描应找到偏后位置的明文");

        // 确认 Hit 消息里 plain 字段是用户的明文
        let mut found_plaintext = false;
        for m in rx.iter() {
            if let EngineMsg::Hit { plain_preview: Some(p), .. } = m {
                if p.as_bytes().starts_with(plaintext) || p == String::from_utf8_lossy(plaintext) {
                    found_plaintext = true;
                    break;
                }
            }
        }
        assert!(found_plaintext, "Hit 消息应包含正确的明文");
    }

    /// 回归: Windows 进程里字符串多以 UTF-16 LE 存储 (每个 ASCII 字符后跟一个
    /// 0x00 字节)。第一遍 ASCII 扫描会把 UTF-16 串在每个 0x00 处切碎, 应该靠
    /// 第二遍 UTF-16 扫描兜住。
    #[test]
    fn streaming_hash_finds_utf16_le_plaintext() {
        use std::sync::mpsc::channel;
        use std::sync::atomic::AtomicBool;

        // 模拟一段较长的 ASCII 明文 (HTTP form body 风格)
        let plaintext = b"ACCOUNT=admin&TOKEN=abc123XYZ&NONCE=987654321&TS=1779876015";
        // SHA-1 摘要
        let ct = {
            use sha1::{Digest, Sha1};
            let mut h = Sha1::new();
            h.update(plaintext);
            h.finalize().to_vec()
        };

        // 构造 dump: UTF-16 LE 编码的明文, 周围塞二进制噪声
        let mut dump: Vec<u8> = Vec::new();
        dump.extend_from_slice(&[0xCC, 0xCC, 0xCC, 0xCC, 0x00, 0xFF, 0x80, 0xA0]);
        for &b in plaintext {
            dump.push(b);
            dump.push(0x00); // UTF-16 LE: ASCII char + 0x00
        }
        dump.extend_from_slice(&[0xCC, 0xCC, 0xCC, 0xCC]);

        let (tx, rx) = channel();
        let stop = AtomicBool::new(false);
        let hits = streaming_hash_match(
            &[Arc::new(dump)],
            &ct,
            &[(AlgoKind::Sha1, "SHA-1")],
            STRING_MIN_LEN,
            HASH_REVERSE_MAX_LEN,
            &stop,
            &tx,
            Instant::now(),
        );
        drop(tx);
        assert!(hits >= 1, "UTF-16 LE 二遍扫描应命中明文的 SHA-1");

        let mut found = false;
        for m in rx.iter() {
            if let EngineMsg::Hit { plain_full: Some(p), .. } = m {
                if p == plaintext {
                    found = true;
                    break;
                }
            }
        }
        assert!(found, "Hit 消息里 plain_full 应等于原始 ASCII 明文");
    }

    /// 回归: 被哈希的 HTTP 明文里几乎一定有 \n 换行 (CRLF / LF 行分隔 form-data
    /// 或多行 JSON), 第一遍 ASCII 扫描必须把 \n 当作字符串内部字节而非分隔符,
    /// 否则整段被切碎, hash 比对永远命中不了。
    #[test]
    fn streaming_hash_finds_plaintext_with_newlines() {
        use std::sync::mpsc::channel;
        use std::sync::atomic::AtomicBool;

        // 模拟 multipart/form-data 风格的多行明文
        let plaintext = b"ACCOUNT=admin\r\nTOKEN=abc123XYZ\r\nNONCE=987\r\nTS=1779876015";
        let ct = {
            use sha1::{Digest, Sha1};
            let mut h = Sha1::new();
            h.update(plaintext);
            h.finalize().to_vec()
        };

        // dump = 二进制噪声 + 明文 + 噪声
        let mut dump: Vec<u8> = Vec::new();
        dump.extend_from_slice(&[0x00; 4096]);
        dump.extend_from_slice(plaintext);
        dump.push(0x00);
        dump.extend_from_slice(&[0xCC; 4096]);

        let (tx, rx) = channel();
        let stop = AtomicBool::new(false);
        let hits = streaming_hash_match(
            &[Arc::new(dump)],
            &ct,
            &[(AlgoKind::Sha1, "SHA-1")],
            STRING_MIN_LEN,
            HASH_REVERSE_MAX_LEN,
            &stop,
            &tx,
            Instant::now(),
        );
        drop(tx);
        assert!(hits >= 1, "含 \\r\\n 的明文应该被识别为一整段并命中");

        let mut found = false;
        for m in rx.iter() {
            if let EngineMsg::Hit { plain_full: Some(p), .. } = m {
                if p == plaintext {
                    found = true;
                    break;
                }
            }
        }
        assert!(found, "Hit 消息里 plain_full 应等于含换行的完整明文");
    }

    /// 回归: 流式对称扫描能从 dump 里恢复加密 key, 即使 key 在偏后位置 (跳过旧的 5M 上限)
    #[test]
    fn streaming_symmetric_recovers_key_late_in_dump() {
        use cipher::BlockEncryptMut;
        use std::sync::mpsc::channel;

        type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;

        let key = b"my_secret_key_16"; // 16 字节
        let iv = [0x33u8; 16];
        let plaintext = br#"{"openkey":"abc","session_id":"u_42","action":"verify_pay"}"#;

        // 加密构造 ct = IV || ciphertext
        let mut buf = vec![0u8; plaintext.len() + 16];
        let ct_len = Aes128CbcEnc::new_from_slices(key, &iv)
            .unwrap()
            .encrypt_padded_b2b_mut::<Pkcs7>(plaintext, &mut buf)
            .unwrap()
            .len();
        let mut ct = iv.to_vec();
        ct.extend_from_slice(&buf[..ct_len]);

        // 构造 dump: 前面塞大量噪声 + key 在偏后位置
        let mut dump = Vec::with_capacity(2_000_000);
        for i in 0..50_000 {
            dump.extend_from_slice(format!("garbage_data_block_{:08}_", i).as_bytes());
        }
        // 隔断
        dump.extend_from_slice(&[0u8; 16]);
        // 真正的 key
        dump.extend_from_slice(key);
        dump.extend_from_slice(&[0u8; 16]);

        // 流式扫描
        let (tx, rx) = channel();
        let stop = AtomicBool::new(false);
        let spec = lookup_spec("aes-cbc").unwrap();
        let hits = streaming_dump_match(
            &[Arc::new(dump)],
            &ct,
            &[spec],
            &[],
            &[],
            "",
            &[],
            false, // 不需要深搜也能命中 (key 长度 16, step=8 → 16 字节对齐够用)
            false,
            &stop,
            &tx,
            Instant::now(),
        );
        drop(tx);

        assert!(hits >= 1, "流式扫描应找到 AES-CBC key");
        let mut found_pt = false;
        for m in rx.iter() {
            if let EngineMsg::Hit {
                plain_preview: Some(p),
                ..
            } = m
            {
                if p.contains("openkey") && p.contains("session_id") {
                    found_pt = true;
                    break;
                }
            }
        }
        assert!(found_pt, "Hit 消息应解出含 'openkey' 'session_id' 的明文");
    }

    /// 回归: 短密文 + 流密码 不应该靠 ASCII 启发式假命中
    #[test]
    fn short_ciphertext_no_ascii_false_positive() {
        // 16 字节随机但 "看起来像 ASCII" 的输出
        let plain_like = b"|B.ktT+uK0\n:9)0B"; // 截图里 RC4 命中的字面值
        assert_eq!(plain_like.len(), 16);
        // 不给关键字 → 不应该当作命中 (短输出无足够上下文)
        assert!(judge_hit(plain_like, "").is_none());
        // 给了不匹配的关键字 → 也不应该当作命中
        assert!(judge_hit(plain_like, "token=").is_none());
        // 给了匹配的子串 → 才命中
        assert!(judge_hit(plain_like, "ktT").is_some());
    }
}
