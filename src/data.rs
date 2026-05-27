use std::collections::HashMap;

pub struct AlgoItem {
    pub id: &'static str,
    pub name: &'static str,
    pub tag: &'static str,
}

pub struct AlgoGroup {
    pub id: &'static str,
    pub name: &'static str,
    pub en: &'static str,
    pub items: &'static [AlgoItem],
}

pub const ALGO_TREE: &[AlgoGroup] = &[
    AlgoGroup {
        id: "hash",
        name: "哈希算法",
        en: "Hash",
        items: &[
            AlgoItem { id: "md5", name: "MD5", tag: "128" },
            AlgoItem { id: "sha1", name: "SHA-1", tag: "160" },
            AlgoItem { id: "sha256", name: "SHA-256", tag: "256" },
            AlgoItem { id: "sha512", name: "SHA-512", tag: "512" },
            AlgoItem { id: "sm3", name: "SM3", tag: "256" },
            AlgoItem { id: "ripemd160", name: "RIPEMD-160", tag: "160" },
        ],
    },
    AlgoGroup {
        id: "hmac",
        name: "HMAC",
        en: "HMAC",
        items: &[
            AlgoItem { id: "hmac-md5", name: "HMAC-MD5", tag: "128" },
            AlgoItem { id: "hmac-sha1", name: "HMAC-SHA-1", tag: "160" },
            AlgoItem { id: "hmac-sha224", name: "HMAC-SHA-224", tag: "224" },
            AlgoItem { id: "hmac-sha256", name: "HMAC-SHA-256", tag: "256" },
            AlgoItem { id: "hmac-sha384", name: "HMAC-SHA-384", tag: "384" },
            AlgoItem { id: "hmac-sha512", name: "HMAC-SHA-512", tag: "512" },
            AlgoItem { id: "hmac-sha3", name: "HMAC-SHA-3", tag: "256" },
            AlgoItem { id: "hmac-ripemd", name: "HMAC-RIPEMD", tag: "160" },
            AlgoItem { id: "hmac-sm3", name: "HMAC-SM3", tag: "256" },
        ],
    },
    AlgoGroup {
        id: "sym",
        name: "对称加密",
        en: "Symmetric",
        items: &[
            AlgoItem { id: "aes-ecb", name: "AES-ECB", tag: "128/192/256" },
            AlgoItem { id: "aes-cbc", name: "AES-CBC", tag: "128/192/256" },
            AlgoItem { id: "aes-cfb", name: "AES-CFB", tag: "128/192/256" },
            AlgoItem { id: "aes-ctr", name: "AES-CTR", tag: "128/192/256" },
            AlgoItem { id: "aes-gcm", name: "AES-GCM", tag: "128/192/256" },
            AlgoItem { id: "des-ecb", name: "DES-ECB", tag: "64" },
            AlgoItem { id: "des-cbc", name: "DES-CBC", tag: "64" },
            AlgoItem { id: "3des-ecb", name: "3DES-ECB", tag: "192" },
            AlgoItem { id: "3des-cbc", name: "3DES-CBC", tag: "192" },
            AlgoItem { id: "sm4-ecb", name: "SM4-ECB", tag: "128" },
            AlgoItem { id: "sm4-cbc", name: "SM4-CBC", tag: "128" },
            AlgoItem { id: "sm4-cfb", name: "SM4-CFB", tag: "128" },
            AlgoItem { id: "rc4", name: "RC4", tag: "*" },
            AlgoItem { id: "chacha20", name: "ChaCha20", tag: "256" },
        ],
    },
    AlgoGroup {
        id: "asym",
        name: "非对称 / 签名",
        en: "Asymmetric",
        items: &[
            AlgoItem { id: "rsa", name: "RSA", tag: "1024/2048" },
            AlgoItem { id: "rsa-pss", name: "RSA-PSS", tag: "*" },
            AlgoItem { id: "sm2", name: "SM2", tag: "256" },
            AlgoItem { id: "ecdsa", name: "ECDSA", tag: "P-256" },
            AlgoItem { id: "ed25519", name: "Ed25519", tag: "256" },
        ],
    },
];

pub fn default_selection() -> HashMap<String, bool> {
    // 已在 engine.rs 中实现的算法默认勾选; 未实现的 (rsa / rsa-pss / sm2 /
    // ecdsa / ed25519) 留空, 防止用户误选后引擎静默跳过。
    let mut m = HashMap::new();
    for id in [
        // 哈希 (全部已实现)
        "md5", "sha1", "sha256", "sha512", "sm3", "ripemd160",
        // HMAC (全部已实现)
        "hmac-md5", "hmac-sha1", "hmac-sha224", "hmac-sha256",
        "hmac-sha384", "hmac-sha512", "hmac-sha3", "hmac-ripemd", "hmac-sm3",
        // 对称 (全部已实现)
        "aes-ecb", "aes-cbc", "aes-cfb", "aes-ctr", "aes-gcm",
        "des-ecb", "des-cbc",
        "3des-ecb", "3des-cbc",
        "sm4-ecb", "sm4-cbc", "sm4-cfb",
        "rc4", "chacha20",
        // 非对称 / 签名: rsa, rsa-pss, sm2, ecdsa, ed25519 暂未实现, 不勾选
    ] {
        m.insert(id.to_string(), true);
    }
    m
}

pub fn algo_name(id: &str) -> &'static str {
    for g in ALGO_TREE {
        for it in g.items {
            if it.id == id {
                return it.name;
            }
        }
    }
    "?"
}

pub struct HistEntry {
    pub when: &'static str,
    pub title: &'static str,
    pub sub: &'static str,
    pub status: HistStatus,
}

pub enum HistStatus { Ok, Warn }

pub const SAMPLE_HISTORY: &[HistEntry] = &[
    HistEntry { when: "06-04 14:22", title: "demo_target.exe", sub: "AES-256-CBC · 命中 · 28s", status: HistStatus::Ok },
    HistEntry { when: "06-04 11:08", title: "ctf_round3.bin", sub: "HMAC-SHA-256 · 未命中 · 2m 14s", status: HistStatus::Warn },
    HistEntry { when: "06-03 19:45", title: "local_test.dmp", sub: "SM4-ECB · 命中 · 8s", status: HistStatus::Ok },
    HistEntry { when: "06-03 16:30", title: "challenge_07.dmp", sub: "DES + HMAC-MD5 · 命中 · 1m 02s", status: HistStatus::Ok },
    HistEntry { when: "06-02 22:11", title: "fuzz_capture.bin", sub: "已取消", status: HistStatus::Warn },
];

pub struct Rule {
    pub on: bool,
    pub name: &'static str,
    pub pat: &'static str,
}

pub fn default_rules() -> Vec<Rule> {
    vec![
        Rule { on: true,  name: "本地测试端 (loopback)", pat: r"http(s)?://(127\.0\.0\.1|localhost)(:\d+)?/.*" },
        Rule { on: true,  name: "Debug API 路径",         pat: r"/debug/api/v\d+/.*" },
        Rule { on: false, name: "CTF 训练靶机",            pat: r"https?://10\.0\.\d+\.\d+/challenge/.*" },
    ]
}
