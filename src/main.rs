#[macro_use]
extern crate simple_error;

use std::{env, fs};

mod crypto_lib;

fn challenge3() {
    let decode_str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let (best_result, best_char) = crypto_lib::decrypt_single_xor(decode_str);
    println!("Decoded with '{}': {}", best_char, best_result)
}

fn args_contain(val: &str) -> bool {
    env::args().any(|x| { x == val.to_string() })
}

fn main() {
    if args_contain("3") {
        challenge3()
    }

    let f_str = fs::read_to_string("data/4.txt").unwrap();
    let lines = f_str.split_whitespace().collect::<Vec<&str>>();

    let mut best_score = 0;
    let mut best_line_number = 0;
    let mut best_line_hex = "";
    let mut best_decrypted = "".to_string();
    for (i, l) in lines.into_iter().enumerate() {
        let decrypted = crypto_lib::decrypt_single_xor(l).0;
        let score = crypto_lib::score_english(&decrypted);

        if score > best_score {
            best_score = score;
            best_line_number = i;
            best_line_hex = l;
            best_decrypted = decrypted;
        }
    }

    println!("Line number {} ({}) decrypts to: {}", best_line_number, best_line_hex, best_decrypted);
}
