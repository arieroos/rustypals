use hex;
use std::error::Error;

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

fn fixed_xor(bytes_a: &mut Vec<u8>, bytes_b: &Vec<u8>) {
    for i in 0..bytes_a.len() {
        bytes_a[i] ^= bytes_b[i]
    }
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
