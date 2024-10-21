use std::fs;
use aes::Aes256;
use pbkdf2::{pbkdf2_hmac};
use sha2::Sha256;
use aes_gcm;
use aes_gcm::{aead, aead::{Aead, AeadCore, KeyInit, consts::U12}, Aes256Gcm, AesGcm, Key, Nonce};


fn main() {
    let vault1_path = "/home/kaladin/Documents/encryptedVault/vaults-plaintext/vault1.json";
    let vault2_path = "/home/kaladin/Documents/encryptedVault/vaults-plaintext/vault2.json";
    let vault3_path = "/home/kaladin/Documents/encryptedVault/vaults-plaintext/vault3.json";

    let encrypted_dir_vault1_hash = "/home/kaladin/Documents/encryptedVault/vaults-encrypted/vault1_hash.txt";
    let encrypted_dir_vault2_hash = "/home/kaladin/Documents/encryptedVault/vaults-encrypted/vault2_hash.txt";
    let encrypted_dir_vault3_hash = "/home/kaladin/Documents/encryptedVault/vaults-encrypted/vault3_hash.txt";

    let encrypted_dir_vault1 = "/home/kaladin/Documents/encryptedVault/vaults-encrypted/vault1_encrypted.json";
    let encrypted_dir_vault2 = "/home/kaladin/Documents/encryptedVault/vaults-encrypted/vault2_encrypted.json";
    let encrypted_dir_vault3 = "/home/kaladin/Documents/encryptedVault/vaults-encrypted/vault3_encrypted.json";

    let vault1 = fs::read_to_string(vault1_path).expect("Could not read vault1 file");
    let vault2 = fs::read_to_string(vault2_path).expect("Could not read vault2 file");
    let vault3 = fs::read_to_string(vault3_path).expect("Could not read vault3 file");


//VAULT 1
    println!("make vault 1");
    //sets the password and salt
    let password = b"!PaperBasketballParkour83";
    let salt = Aes256Gcm::generate_nonce().expect("error with salt");
    //println!("salt {:?}", salt);

    //run through the kdf's
    let key = create_hash(password, salt.as_slice());
    let hash = createkey(password, salt.as_slice());

    //makes the vaults
    make_the_vault(key, hash, salt, vault1, encrypted_dir_vault1, encrypted_dir_vault1_hash);

 //VAULT 2
    println!("make vault 2");
    let password = b"Ti84NintendoPacman";
    let salt = Aes256Gcm::generate_nonce().expect("error with salt");
    //println!("salt {:?}", salt);
    let key = create_hash(password, salt.as_slice());
    let hash = createkey(password, salt.as_slice());

    make_the_vault(key, hash, salt, vault2, encrypted_dir_vault2, encrypted_dir_vault2_hash);

//VAULT 3
    println!("make vault 3");
    let password = b"ArrakisThirstSand";
    let salt = Aes256Gcm::generate_nonce().expect("error with salt");
    //println!("salt {:?}", salt);
    let key = create_hash(password, salt.as_slice());
    let hash = createkey(password, salt.as_slice());

    make_the_vault(key, hash, salt, vault3, encrypted_dir_vault3, encrypted_dir_vault3_hash);

}

fn create_hash(password : &[u8], salt : &[u8]) -> [u8; 32] {
    let n = 100101;
    let mut hash = [0u8; 32];
    pbkdf2_hmac::<Sha256>(&password, &salt, n, &mut hash);
    println!("hash: {:?}\n", hash);
    hash
}

fn createkey(password : &[u8], salt : &[u8]) -> [u8; 32] {
    let n = 100100;
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(&password, &salt, n, &mut key);
    println!("key: {:?}\n", key);
    key
}

fn make_the_vault(key: [u8; 32], hash: [u8;32], salt : aead::Nonce<AesGcm<Aes256, U12>>, vault: String, encrypted_vault: &str, encrypted_hash: &str ) {
    //encrypt the vault
    let key: &Key<Aes256Gcm> = key.as_slice().try_into().expect("issue making the key for encryption");
    let cipher = Aes256Gcm::new(key);
    let binding = salt.to_vec();
    let salt_binding = Nonce::from_slice(&binding);
    let cipher_text = cipher.encrypt(&salt_binding, vault.as_bytes()).expect("error encrypting");
    //println!("encrypted vault1: {:?}\n", cipher_text.clone());

    //convert to json
    let json = serde_json::to_string(&cipher_text.clone()).expect("problem converting to json");
    println!("json: {:?}\n", json.clone());

    //check the encryption
    println!("check by decrypting \n");
    let cipher_text2:Vec<u8> = serde_json::from_str(&json).expect("error converting from json");
    let plain = cipher.decrypt(salt_binding, cipher_text2.as_slice()).expect("error decrypting");
    println!("decrypted vault1: {:?}\n", String::from_utf8(plain).unwrap());

    //write to files
    fs::write(encrypted_hash, format!("hash: {:?}\nsalt: {:?}", hash,salt_binding.clone())).expect("Could not write vault1 file");
    fs::write(encrypted_vault, format!("{:?}", json)).expect("Could not write vault1 file");
}