use hmac::{Hmac, Mac};
use sha2::Sha512;

type HashT = [u8; 32];
type HmacSha512 = Hmac<Sha512>;

pub fn hmac_sha512(seed: &HashT, key: &HashT) -> (HashT, HashT) {
    let mut mac = HmacSha512::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(seed);
    let result = mac.finalize().into_bytes();

    let mut out1 = [0u8; 32];
    let mut out2 = [0u8; 32];
    out1.copy_from_slice(&result[..32]);
    out2.copy_from_slice(&result[32..]);

    (out1, out2)
}

pub fn hmac_sha512_n(seed: &HashT, key: &HashT, index: u32) -> (HashT, HashT) {
    let mut mac = HmacSha512::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(seed);

    let bindex: [u8; 4] = index.to_be_bytes();
    // let reverse_index = bindex.iter().rev().cloned().collect::<Vec<u8>>();
    mac.update(&bindex);

    let result = mac.finalize().into_bytes();

    let mut out1 = [0u8; 32];
    let mut out2 = [0u8; 32];
    out1.copy_from_slice(&result[..32]);
    out2.copy_from_slice(&result[32..]);

    (out1, out2)
}

pub fn kdf_hmac_sha512(seed: &HashT, key: &HashT, num_iters: u32) -> (HashT, HashT) {
    let mut tmp = [0u8; 64];

    let mut mac = HmacSha512::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(seed);
    tmp.copy_from_slice(&mac.finalize().into_bytes());

    for _ in 1..num_iters {
        mac = HmacSha512::new_from_slice(&tmp).expect("HMAC can take key of any size");
        mac.update(seed);
        tmp.copy_from_slice(&mac.finalize().into_bytes());
    }

    let mut out1 = [0u8; 32];
    let mut out2 = [0u8; 32];
    out1.copy_from_slice(&tmp[..32]);
    out2.copy_from_slice(&tmp[32..]);

    (out1, out2)
}