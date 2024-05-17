mod cryptography;

use cryptography::convert_to_hex_string;

fn main() {
    let mut array_username = hex::decode(convert_to_hex_string("teste")).expect("Decoding failed");
    let padding_required = 16 - array_username.len() % 16;
    if padding_required != 16 {
        array_username.extend(vec![0u8; padding_required]);
    }

    let result = array_username.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();

    println!("{}", result);
}