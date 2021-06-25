use hex;
use std::error::Error;

fn hex_to_base64(hex_str: &str) -> Result<String, Box<dyn Error>> {
    Ok(base64::encode(hex::decode(hex_str)?))
}

#[cfg(test)]
mod crypto_test {
    use crate::crypto_lib::hex_to_base64;

    #[test]
    fn test_hex_to_base64() {
        let res = hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
        assert_eq!(res.unwrap(), String::from("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"))
    }
}
