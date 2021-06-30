#[macro_use]
extern crate simple_error;

mod crypto_lib;

fn main() {
    let decode_str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let try_str = "etaoin shrdlu";

    let mut best_char = 'e';
    let mut best_score = 0;
    let mut best_result = "".to_string();

    for c in try_str.as_bytes() {
        let result = crypto_lib::try_decrypt_single_xor(decode_str, *c);

        let chars = result.chars().collect::<Vec<char>>();
        let score = crypto_lib::histogram_for(&chars)
            .into_iter()
            .fold(0, |acc, x| {
                let m = match (try_str.contains(*x.0), x.0.is_alphanumeric()) {
                    (true, _) => 2,
                    (_, true) => 1,
                    _ => 0
                };
                acc + (x.1 * m)
            });

        if score > best_score {
            best_score = score;
            best_char = *c as char;
            best_result = result;
        }
    }

    println!("Decoded for '{}': {}", best_char, best_result)
}
