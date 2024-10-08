use std::io::stdin;
use pbkdf2::{pbkdf2_hmac};
use sha2::Sha256;

fn main() {

    let password = "password\n"; //interestingly the way the input is taken, the new line is read in.
    let salt = b"this is the salt";

    let n = 100100 + 1; //this can be user input, but I put it here so that its easy to change. 100101 does not take long (1 second)

    let hash = create_hash(password.as_bytes(), salt, n); //outputs the hashed password
    println!("this is the hashed password: {:?}", hash);

    println!("Can you get in the vault?");
    print!("Enter password below: \n");
    //this just takes user input
    let mut guessed_password = String::new();
    stdin().read_line(&mut guessed_password).expect("error: unable to read user input");

    vault(guessed_password.as_bytes(), salt, n, hash); // the vault is hashing a new password based on input and compares it to the given hashed password
}

fn create_hash(password : &[u8], salt : &[u8], n: u32) -> [u8; 20] {
    let mut key = [0u8; 20];
    pbkdf2_hmac::<Sha256>(&password, &salt, n, &mut key);
    //println!("key1: {:?}", key); //print statement for debug
    key
}

fn vault(password : &[u8], salt : &[u8], n: u32, hashed_password:[u8; 20] ) {
    let mut key = [0u8; 20];
    pbkdf2_hmac::<Sha256>(&password, &salt, n, &mut key);
    //pbkdf2::<Hmac<Sha256>>(password, salt, n, &mut key).expect("issue with encrypting password"); //the rust page for pbkdf2 suggests this method
    //println!("key2: {:?}", key); //print statement for debug
    assert_eq!(key, hashed_password);
    println!("password correct! Here is the secret you are looking for:");
    println!("The meaning of life is... 42!!");

}