use hex;
use std::error::Error;
use std::collections::HashMap;
use std::hash::Hash;

const COMMON_ENGLISH_CHARS: &str = "etaoin shrdluETAOINSHRDLU";

fn hex_to_base64(hex_str: &str) -> Result<String, Box<dyn Error>> {
    Ok(base64::encode(hex::decode(hex_str)?))
}

pub fn hex_to_utf8(hex_str: &str) -> Result<String, Box<dyn Error>> {
    Ok(hex::decode(hex_str)?.into_iter().map(|x| { x as char }).collect())
}

fn fixed_xor_hex(hex_str_a: &str, hex_str_b: &str) -> Result<String, Box<dyn Error>> {
    if hex_str_a.len() != hex_str_b.len() {
        bail!("hex strings must be of same length")
    }

    let mut bytes_a = hex::decode(hex_str_a)?;
    let bytes_b = hex::decode(hex_str_b)?;
    fixed_xor(&mut bytes_a, &bytes_b);

    Ok(hex::encode(bytes_a))
}

pub fn fixed_xor(bytes_a: &mut Vec<u8>, bytes_b: &Vec<u8>) {
    for i in 0..bytes_a.len() {
        bytes_a[i] ^= bytes_b[i]
    }
}

pub fn histogram_for<T: Hash + Eq>(input: &Vec<T>) -> HashMap<&T, i32> {
    let mut histogram = HashMap::new();
    for e in input.iter() {
        let v = *histogram.entry(e).or_insert(0);
        histogram.insert(e, v + 1);
    };
    return histogram;
}

pub fn score_english(sentence: &String) -> i32 {
    let chars = sentence.chars().collect::<Vec<char>>();

    histogram_for(&chars)
        .into_iter()
        .fold(0, |acc, x| {
            let m = match (COMMON_ENGLISH_CHARS.contains(*x.0), x.0.is_alphanumeric()) {
                (true, _) => 2,
                (_, true) => 1,
                _ => 0
            };
            acc + (x.1 * m)
        })
}

pub fn try_decrypt_single_xor(decode_str: &str, attempt_with: u8) -> String {
    let mut enc_bytes = hex::decode(decode_str).unwrap();

    let most_frequent = histogram_for(&enc_bytes)
        .into_iter().max_by_key(|a| { a.1 })
        .unwrap().0;

    let xor_byte = most_frequent ^ (attempt_with);
    let xor_bytes = vec![xor_byte; enc_bytes.len()];
    fixed_xor(&mut enc_bytes, &xor_bytes);

    enc_bytes.into_iter().map(|b| { b as char }).collect::<String>()
}

pub fn decrypt_single_xor(decode_str: &str) -> (String, char) {
    let try_str = COMMON_ENGLISH_CHARS;

    let mut best_char = 'e';
    let mut best_score = 0;
    let mut best_result = "".to_string();

    for c in try_str.as_bytes() {
        let result = try_decrypt_single_xor(decode_str, *c);

        let score = score_english(&result);
        if score > best_score {
            best_score = score;
            best_char = *c as char;
            best_result = result;
        }
    };
    return (best_result, best_char);
}

pub fn repeating_key_xor<T: AsRef<[u8]>>(to_encrypt: T, key: T) -> Vec<u8> {
    let key_ref = key.as_ref();
    to_encrypt.as_ref().iter().enumerate()
        .map(|(i, c)| { key_ref[i % key_ref.len()] ^ *c })
        .collect()
}

fn hamming_byte(b1: u8, b2: u8) -> usize {
    let mut c: usize = 0;
    let comp = b1 ^ b2;
    for i in 0..8 {
        let mask: u8 = 1 << i;
        if comp & mask > 0 {
            c += 1;
        }
    }
    return c;
}

pub fn hamming_distance<S: AsRef<[u8]>>(str1: S, str2: S) -> usize {
    let (b1, b2) = (str1.as_ref(), str2.as_ref());
    if b1.len() != b2.len() {
        return 0;
    }
    b1.iter()
        .zip(b2.iter())
        .fold(0, |acc, (a, b)| { acc + hamming_byte(*a, *b) })
}

#[cfg(test)]
mod crypto_test {
    use crate::crypto_lib::{hex_to_base64, fixed_xor_hex, hamming_distance};

    #[test]
    fn test_hex_to_base64() {
        let res = hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
        assert_eq!(res.unwrap(), String::from("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"))
    }

    #[test]
    fn test_fixed_xor() {
        let res = fixed_xor_hex("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965").unwrap();
        assert_eq!(res, String::from("746865206b696420646f6e277420706c6179"))
    }

    #[test]
    fn test_hamming_distance() {
        let res = hamming_distance("this is a test", "wokka wokka!!!");
        assert_eq!(res, 37)
    }
}
