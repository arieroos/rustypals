use hex;
use std::error::Error;
use std::collections::HashMap;
use std::hash::Hash;

const COMMON_ENGLISH_CHARS: &str = "etaoin shrdluETAOINSHRDLU";

#[allow(dead_code)]
fn hex_to_base64(hex_str: &str) -> Result<String, Box<dyn Error>> {
    Ok(base64::encode(hex::decode(hex_str)?))
}

#[allow(dead_code)]
pub fn hex_to_utf8(hex_str: &str) -> Result<String, Box<dyn Error>> {
    Ok(hex::decode(hex_str)?.into_iter().map(|x| { x as char }).collect())
}

#[allow(dead_code)]
fn fixed_xor_hex(hex_str_a: &str, hex_str_b: &str) -> Result<String, Box<dyn Error>> {
    if hex_str_a.len() != hex_str_b.len() {
        bail!("hex strings must be of same length")
    }

    let bytes_a = hex::decode(hex_str_a)?;
    let bytes_b = hex::decode(hex_str_b)?;
    let res = fixed_xor(bytes_a, bytes_b);

    Ok(hex::encode(res))
}

pub fn fixed_xor<T: AsRef<[u8]>>(bytes_a: T, bytes_b: T) -> Vec<u8> {
    let (a, b) = (bytes_a.as_ref(), bytes_b.as_ref());
    a.iter().zip(b.iter()).map(|(x, y)| { x ^ y }).collect()
}

pub fn histogram_for<T: Hash + Eq>(input: &Vec<T>) -> HashMap<&T, i32> {
    let mut histogram = HashMap::new();
    for e in input.iter() {
        let v = *histogram.entry(e).or_insert(0);
        histogram.insert(e, v + 1);
    };
    return histogram;
}

pub fn score_english<T: AsRef<[u8]>>(sentence: T) -> i32 {
    let chars = sentence.as_ref()
        .iter().map(|x| {*x as char})
        .collect();

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

pub fn try_decrypt_single_xor<T: AsRef<[u8]>>(decode_str: T, attempt_with: u8) -> Vec<u8> {
    let enc_bytes = decode_str.as_ref()
        .iter().map(|x| { *x })
        .collect::<Vec<u8>>();

    let most_frequent = histogram_for(&enc_bytes)
        .into_iter().max_by_key(|a| { a.1 })
        .unwrap().0;

    let xor_byte = most_frequent ^ (attempt_with);
    let xor_bytes = vec![xor_byte; enc_bytes.len()];
    fixed_xor(&enc_bytes, &xor_bytes)
}

pub fn decrypt_single_xor<T: AsRef<[u8]>>(cypher_text: T) -> (Vec<u8>, u8) {
    let try_str = COMMON_ENGLISH_CHARS;
    let cypher_bytes = cypher_text.as_ref();

    let mut key = b'e';
    let mut best_score = 0;
    let mut best_result= Vec::new();

    for c in try_str.as_bytes() {
        let result = try_decrypt_single_xor(cypher_bytes, *c);

        let score = score_english(&result);
        if score > best_score {
            best_score = score;
            key = *c ^ result[0];
            best_result = result;
        }
    };
    return (best_result, key);
}

pub fn repeating_key_xor<T: AsRef<[u8]>>(to_encrypt: T, key: T) -> Vec<u8> {
    let key_ref = key.as_ref();
    to_encrypt.as_ref().iter().enumerate()
        .map(|(i, c)| { key_ref[i % key_ref.len()] ^ *c })
        .collect()
}

fn hamming_byte(b1: u8, b2: u8) -> usize {
    let mut c = 0;
    let comp = b1 ^ b2;
    for i in 0..8 {
        let mask: u8 = 1 << i;
        if comp & mask > 0 {
            c += 1;
        }
    }
    return c;
}

pub fn hamming_distance<S: AsRef<[u8]>>(str1: S, str2: S) -> Result<usize, String> {
    let (b1, b2) = (str1.as_ref(), str2.as_ref());
    if b1.len() != b2.len() {
        return Err("lengths don't match".to_string());
    }
    let sum = b1.iter()
        .zip(b2.iter())
        .fold(0, |acc, (a, b)| { acc + hamming_byte(*a, *b) });
    return Ok(sum);
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
