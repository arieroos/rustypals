#[macro_use]
extern crate simple_error;

use hex;
use std::{env, fs};
use std::cmp::{max, min};
use std::str;
use hex::decode;

mod crypto_lib;

fn challenge3() {
    let decode_str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let cypher_bytes = hex::decode(decode_str).unwrap();
    let (best_result, best_char) = crypto_lib::decrypt_single_xor(cypher_bytes);
    let out = str::from_utf8(&best_result).unwrap_or("definitely wrong");
    println!("Decoded with '{}': {:?}", best_char as char, out)
}

fn challenge4() {
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
            best_decrypted = str::from_utf8(&decrypted).unwrap_or("").to_string();
        }
    }

    println!("Line number {} ({}) decrypts to: {}", best_line_number, best_line_hex, best_decrypted);
}

fn challenge5() {
    let to_encrypt = [
        "Burning 'em, if you ain't quick and nimble",
        "I go crazy when I hear a cymbal"
    ];
    let key = "ICE";

    for l in to_encrypt {
        let encrypted = crypto_lib::repeating_key_xor(l, key);
        println!("{}", hex::encode(encrypted))
    }
}

fn args_contain(val: &str) -> bool {
    env::args().any(|x| { x == val.to_string() })
}

fn main() {
    if args_contain("3") {
        challenge3();
        return;
    }
    if args_contain("4") {
        challenge4();
        return;
    }
    if args_contain("5") {
        challenge5();
        return;
    }

    let cypher_bytes = base64::decode("HUIfTQsPAh9PE048GmllH0kcDk4TAQsHThsBFkU2AB4BSWQgVB0dQzNTTmVS").unwrap();
    const COMP_BLOCKS: usize = 4;
    const DISTANCES: usize = (COMP_BLOCKS * (COMP_BLOCKS - 1)) / 2;

    let key_lengths: Vec<usize> = (2..=(cypher_bytes.len() / COMP_BLOCKS)).collect();

    let mut key_size = 2;
    let mut best_score = f64::MAX;

    for kl in key_lengths {
        let mut blocks: [&[u8]; COMP_BLOCKS] = [&[]; COMP_BLOCKS];
        for i in 0..COMP_BLOCKS {
            let idx = i * kl;
            blocks[i] = &cypher_bytes[idx..(idx + kl)]
        }

        let mut total_distance = 0;
        for block in 0..COMP_BLOCKS {
            for i in (block + 1)..COMP_BLOCKS {
                total_distance += crypto_lib::hamming_distance(blocks[block], blocks[i])
                    .unwrap();
            }
        }
        let avg_score = total_distance as f64 / DISTANCES as f64;
        let normalised = avg_score / kl as f64;

        if normalised < best_score {
            best_score = normalised;
            key_size = kl;
        }
    }

    let block_count = cypher_bytes.len() / key_size
        + if cypher_bytes.len() % key_size > 0 { 1 } else { 0 };
    let mut blocks = Vec::with_capacity(block_count);
    for i in 0..block_count {
        let start = i * key_size;
        let end = min(start + key_size, block_count * key_size);

        blocks.push(&cypher_bytes[start..end]);
        println!("{}", hex::encode(blocks[i]))
    }
    println!();

    let mut transposed = Vec::with_capacity(key_size);
    for i in 0..key_size {
        transposed.push(Vec::with_capacity(block_count));
        for j in 0..block_count {
            transposed[i].push(cypher_bytes[j * key_size + i]);
        }
        println!("{}", hex::encode(&transposed[i].as_slice()))
    }

    for vec in transposed {
        // let (decoded, _) = crypto_lib::decrypt_single_xor()
    }
}
