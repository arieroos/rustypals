use hex;
use std::error::Error;
use std::collections::HashMap;

fn hex_to_base64(hex_str: &str) -> Result<String, Box<dyn Error>> {
    Ok(base64::encode(hex::decode(hex_str)?))
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

pub fn try_decrypt_single_xor(decode_str: &str, attempt_with: u8) -> String {
    let mut enc_bytes = hex::decode(decode_str).unwrap();
    let mut frequencies = HashMap::new();

    for b in enc_bytes.iter() {
        let v = *frequencies.entry(b).or_insert(0);
        frequencies.insert(b, v + 1);
    }

    let mut most_frequent = frequencies
        .into_iter().max_by_key(|a| { a.1 })
        .unwrap().0;

    let xor_byte = most_frequent ^ (attempt_with);
    let xor_bytes = vec![xor_byte; enc_bytes.len()];
    fixed_xor(&mut enc_bytes, &xor_bytes);

    enc_bytes.into_iter().map(|b| { b as char }).collect::<String>()
}

#[cfg(test)]
mod crypto_test {
    use crate::crypto_lib::{hex_to_base64, fixed_xor_hex};

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
}
