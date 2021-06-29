#[macro_use]
extern crate simple_error;

mod crypto_lib;

use hex;
use std::collections::HashMap;
use crate::crypto_lib::try_decrypt_single_xor;

fn main() {
    let decode_str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

    println!("{}", try_decrypt_single_xor(decode_str, ' ' as u8))
}
