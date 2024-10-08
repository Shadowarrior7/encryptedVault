use std::io::stdin;
use pbkdf2::{pbkdf2_hmac};
use sha2::Sha256;

fn main() {

    let password = "password\n";
    let salt = b"this is the salt";

    let n = 100100 + 1;

    let hash = create_hash(password.as_bytes(), salt, n);
    println!("this is the hashed password: {:?}", hash);

    println!("Can you get in the vault?");
    print!("Enter password below: \n");
    let mut guessed_password = String::new();
    stdin().read_line(&mut guessed_password).expect("error: unable to read user input");

    vault(guessed_password.as_bytes(), salt, n, hash);
}

fn create_hash(password : &[u8], salt : &[u8], n: u32) -> [u8; 20] {
    let mut key = [0u8; 20];
    pbkdf2_hmac::<Sha256>(&password, &salt, n, &mut key);
    //println!("key1: {:?}", key);
    key
}

fn vault(password : &[u8], salt : &[u8], n: u32, hashed_password:[u8; 20] ) {
    let mut key = [0u8; 20];
    pbkdf2_hmac::<Sha256>(&password, &salt, n, &mut key);
    //pbkdf2::<Hmac<Sha256>>(password, salt, n, &mut key).expect("issue with encrypting password");
    //println!("key2: {:?}", key);
    assert_eq!(key, hashed_password);
    println!("password correct! Here is the secret you are looking for:");
    println!("The meaning of life is... 42!!");

}