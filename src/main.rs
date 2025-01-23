use bip39::Mnemonic;
use bech32::{self, Bech32m};
use secp256k1::{PublicKey, SecretKey, Secp256k1};
use sha2::{Digest, Sha256};
use std::convert::TryInto;
use hex;
use rand_core::{RngCore, OsRng};
use std::fs::File;
use std::io::Write;
use inquire::{Text, Confirm, Select};

mod mmx_hmac;
use mmx_hmac::{hmac_sha512_n, kdf_hmac_sha512};

struct KeyPair {
    sk: [u8; 32],
    pk: [u8; 33]
}

struct Keys {
    mnemonic: Mnemonic,
    seed: [u8; 32],
    farmer_key: String,
    addresses: Vec<Addr>,
}

impl KeyPair { //get public key from secret key with secp256k1
    pub fn from_secret_key(secret_key: &SecretKey) -> KeyPair {
        let secp = Secp256k1::new();
        let public_key = PublicKey::from_secret_key(&secp, secret_key);
        let pk = public_key.serialize();
        KeyPair {
            sk: secret_key[..].try_into().unwrap(),
            pk: pk.try_into().unwrap(),
        }
    }
}
impl Keys {
    pub fn generate(entropy: String, passphrase: &str, num_addr: u32) -> Keys {
        let mut hasher: Sha256 = Sha256::new();
        hasher.update(entropy.as_bytes());
        let mut random: [u8; 32] = [0u8; 32];
        OsRng.fill_bytes(&mut random);
        hasher.update(random);
        let seed: [u8; 32] = hasher.finalize().into();
        let farm_key = Keys::seed_to_farmer_key(&seed);
        let mut addresses: Vec<Addr> = Vec::new();
        for i in 0..num_addr {
            let addr = Keys::seed_to_address(&seed, passphrase, i);
            addresses.push(addr);
        }
        let mut r_seed = seed;
        r_seed.reverse();
        let mnemonic = Mnemonic::from_entropy(&r_seed).unwrap();
        Keys {
            mnemonic,
            seed,
            farmer_key: farm_key,
            addresses,
        }
    }

    pub fn seed_to_farmer_key(seed: &[u8; 32]) -> String {
        const KDF_ITERS: u32 = 4096;
        let mmx_seed = "MMX/farmer_keys";
        let mut hasher = Sha256::new();
        hasher.update(mmx_seed.as_bytes());
        let hashphrase: [u8; 32] = hasher.finalize().into();
        let (master1, master2) = kdf_hmac_sha512(&seed, &hashphrase, KDF_ITERS);
        let (chain1, _chain2) = hmac_sha512_n(&master1, &master2, 0);
        let sec_key: SecretKey = SecretKey::from_slice(&chain1).unwrap();
        let keypair: KeyPair = KeyPair::from_secret_key(&sec_key);
        let hex_pubkey = hex::encode(keypair.pk).to_uppercase();
        hex_pubkey
    }

    pub fn seed_to_address(seed: &[u8; 32], passphrase: &str, index: u32) -> Addr {
        const KDF_ITERS: u32 = 4096;
        let mmx_seed = "MMX/seed/";
        let mut hasher = Sha256::new();
        hasher.update(mmx_seed.as_bytes());
        hasher.update(passphrase.as_bytes());
        let hashphrase: [u8; 32] = hasher.finalize().into();
        let (master1, master2) = kdf_hmac_sha512(&seed, &hashphrase, KDF_ITERS);
        let (chain1, chain2) = hmac_sha512_n(&master1, &master2, 11337);
        let (account1, account2) = hmac_sha512_n(&chain1, &chain2, 0);
        let (key1, _key2) = hmac_sha512_n(&account1, &account2, index);
        let sec_key: SecretKey = SecretKey::from_slice(&key1).unwrap();
        let keypair: KeyPair = KeyPair::from_secret_key(&sec_key);
        let addr: Addr = Addr::from_pubkey(&keypair.pk);
        addr
    }
}

struct Addr {
    bits: [u8; 32],
}

impl Addr {
    pub fn from_pubkey(pk: &[u8; 33]) -> Addr {
        let mut hasher = Sha256::new();
        hasher.update(pk);
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        Addr {
            bits: out
        }
    }
    pub fn to_string(&self) -> String {
        let mut dp = self.bits;
        dp.reverse();

        // Encode the byte array using Bech32
        let hrp = bech32::Hrp::parse_unchecked("mmx");
        bech32::encode::<Bech32m>(hrp, &dp).unwrap()
    }
    pub fn from_string(s: &str) -> Addr {
        let (_hrp, dp) = bech32::decode(s).unwrap();
        let mut bits: [u8; 32] = [0u8; 32];
        // reverse byte array for mmx
        bits.copy_from_slice(&dp);
        bits.reverse();
        Addr {
            bits
        }
    }
}

fn export(keys: &Keys, filename: &str) {
    let filepath = format!("{}.txt", filename);
    let mut file = File::create(filepath).unwrap();
    let mut export = String::new();
    export.push_str(&format!("Farmer Public Key: {:?}\n", &keys.farmer_key));
    export.push_str("Addresses: \n");
    for addr in &keys.addresses {
        export.push_str(&format!("{}\n", addr.to_string()));
    }
    file.write_all(export.as_bytes()).unwrap();
}
fn main() {
    loop {
        let mut passphrase = String::from("");
        let pass = Confirm::new("Do you want to use a passphrase for the wallet?")
            .with_default(false).prompt();
        match pass {
            Ok(true) => {
                passphrase = Text::new("Enter a passphrase for the wallet:").prompt().unwrap();
            },
            Ok(false) => {
                passphrase = String::from("");
            },
            Err(_) => println!("Invalid input")
        }
        let entropy = Text::new("Enter entropy for the mnemonic:").prompt().unwrap();
        let addr_options: Vec<String> = vec!["1".to_string(), "5".to_string(), "10".to_string(), "20".to_string()];
        let num_addr_choice = Select::new("How many addresses do you want to generate?", addr_options)
            .prompt()
            .unwrap();
        let num_addr: u32 = num_addr_choice.parse().unwrap();
        let keys = Keys::generate(entropy, &passphrase, num_addr);
        println!("Mnemonic: {:?}", keys.mnemonic.to_string());
        println!("Farmer Key: {}", keys.farmer_key);
        println!("Addresses: ");
        for addr in &keys.addresses {
            println!("{}", addr.to_string());
        }
        let export_choice = Confirm::new("Do you want to export the farmer key and addresses to a file?")
            .with_default(false).prompt();
        match export_choice {
            Ok(true) => {
                let filename = Text::new("Enter a filename:").prompt().unwrap();
                export(&keys, &filename);
            },
            Ok(false) => (),
            Err(_) => println!("Invalid input")
        }
        let again = Confirm::new("Do you want to generate another mnemonic?")
            .with_default(false).prompt();
        match again {
            Ok(true) => (),
            Ok(false) => {
                println!("Exiting...");
                break
            },
            Err(_) => println!("Invalid input")
        }
    }
}