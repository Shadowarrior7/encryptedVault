use std::io::stdin;
use std::fs;
use std::io::{self, Write};
use std::process::Command;
use std::path::{Path, PathBuf};
use pbkdf2::{pbkdf2_hmac};
use sha2::Sha256;
use serde_json::Value;
use aes_gcm;
use aes::Aes256;
use aes::cipher::{BlockCipherEncrypt, BlockCipherDecrypt, KeyInit, array, Array};
use aes::cipher::array::ArrayN;
use aes_gcm::Aes256Gcm;
use crypto_common;
use crypto_common::Key;
use crypto_common::Block;
use generic_array;
use generic_array::GenericArray;

fn main() {
    let vault1_path = "/home/kaladin/Documents/encryptedVault/vaults-plaintext/vault1.json";
    let vault2_path = "/home/kaladin/Documents/encryptedVault/vaults-plaintext/vault2.json";
    let vault3_path = "/home/kaladin/Documents/encryptedVault/vaults-plaintext/vault3.json";

    let encrypted_dir = "/home/kaladin/Documents/encryptedVault/vaults-encrypted";

    let vault1 = fs::read_to_string(vault1_path).expect("Could not read vault1 file");
    // let vault1_deseralized: Value = serde_json::from_str(&vault1).expect("Error Serializing signed_message");
    // let vault1_string= serde_json::to_string(&vault1_deseralized).expect("Error deserializing vault1");
    println!("{:?}", vault1);
    //println!("{:?}", vault1_string);

    let vault2 = fs::read_to_string(vault2_path).expect("Could not read vault2 file");
    let vault3 = fs::read_to_string(vault3_path).expect("Could not read vault3 file");

    println!("make vault 1");
    let password = b"password1";
    let salt = b"this is the salt";
    let key = create_hash(password, salt);
    let hash = createkey(password, salt);
    let key:Key<Aes256> = key.try_into().expect("issue");
    let cipher = Aes256::new(&key);
    let block_size = vault1;
    let mut block = vault1.as_bytes();
    let encrypted_vault1 = cipher.encrypt_block(&mut block);
    println!("{:?}", encrypted_vault1);
    //fs::write(encrypted_dir, encrypted_vault1).expect("Could not write vault1 file");

    println!("make vault 2");
    let password = b"password2"; 
    let salt = b"this is the salt";
    create_hash(password, salt);
    createkey(password, salt);

    println!("make vault 3");
    let password = b"password3";
    let salt = b"this is the salt";
    create_hash(password, salt);
    createkey(password, salt);
}

fn create_hash(password : &[u8], salt : &[u8]) -> [u8; 32] {
    let n = 100101;
    let mut hash = [0u8; 32];
    pbkdf2_hmac::<Sha256>(&password, &salt, n, &mut hash);
    println!("hash: {:?}", hash);
    hash
}

fn createkey(password : &[u8], salt : &[u8]) -> [u8; 32] {
    let n = 100100;
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(&password, &salt, n, &mut key);
    println!("key: {:?}", key);
    key
}