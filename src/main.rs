#[macro_use]
extern crate simple_error;

use std::env;

mod crypto_lib;

fn challenge3() {
    let decode_str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let (best_result, best_char) = crypto_lib::decrypt_single_xor(decode_str);
    println!("Decoded with '{}': {}", best_char, best_result)
}

fn args_contain(val: &str) -> bool {
    env::args().any(|x| {x == val.to_string()})
}

fn main() {
    if args_contain("3") {
        challenge3()
    }
}
