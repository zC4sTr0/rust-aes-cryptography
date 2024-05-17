use aes::Aes128;
use block_modes::{BlockMode, Ecb, block_padding::NoPadding};
use hex;
use thiserror::Error;

const KEY_LAUNCHER: &str = "FAAA85AA40AAAAAAAAAAAA7AAAAAAAAA";
const KEY_BROKER: &str = "AAAAA5AA41BFCAAAAAAAAAA3AA84AA3AA";

type Aes128Ecb = Ecb<Aes128, NoPadding>;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Block mode error")]
    BlockModeError(#[from] block_modes::BlockModeError),
    #[error("Hex decode error")]
    HexDecodeError(#[from] hex::FromHexError),
    #[error("Invalid key or IV length")]
    InvalidKeyIvLength,
    #[error("unknown crypto error")]
    Unknown,
}

impl From<block_modes::InvalidKeyIvLength> for CryptoError {
    fn from(_: block_modes::InvalidKeyIvLength) -> Self {
        CryptoError::InvalidKeyIvLength
    }
}

pub fn string_decode(input_bytes: &[u8]) -> String {
    input_bytes.iter()
        .take_while(|&&x| x != 0)
        .map(|&x| x as char)
        .collect()
}

pub fn aes_decrypt_block(block: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher: Ecb<Aes128, NoPadding> = Aes128Ecb::new_from_slices(key, &[])?;
    let mut buffer = block.to_vec();
    cipher.decrypt(&mut buffer)?;
    Ok(buffer)
}

pub fn aes_encrypt_block(block: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher: Ecb<Aes128, NoPadding> = Aes128Ecb::new_from_slices(key, &[])?;
    let mut buffer: Vec<u8> = block.to_vec();
    let buffer_len: usize = buffer.len();
    cipher.encrypt(&mut buffer, buffer_len)?;
    Ok(buffer)
}

pub fn gunbound_static_encrypt(block: &[u8], encryption_type: u8) -> Result<Vec<u8>, CryptoError> {
    match encryption_type {
        1 => aes_encrypt_block(block, &hex::decode(KEY_LAUNCHER)?),
        2 => aes_encrypt_block(block, &hex::decode(KEY_BROKER)?),
        _ => Err(CryptoError::BlockModeError(block_modes::BlockModeError)),
    }
}

pub fn gunbound_static_decrypt(block: &[u8], encryption_type: u8) -> Result<Vec<u8>, CryptoError> {
    match encryption_type {
        1 => aes_decrypt_block(block, &hex::decode(KEY_LAUNCHER)?),
        2 => aes_decrypt_block(block, &hex::decode(KEY_BROKER)?),
        _ => Err(CryptoError::BlockModeError(block_modes::BlockModeError)),
    }
}

pub fn convert_to_hex_string(input: &str) -> String {
    input.chars()
        .map(|c| format!("{:02x}", c as u8))
        .collect()
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_padding() {
        let mut array_username = hex::decode(convert_to_hex_string("samuelrizzo")).expect("Decoding failed");
        let padding_required = 16 - array_username.len() % 16;
        if padding_required != 16 {
            array_username.extend(vec![0u8; padding_required]);
        }

        let result: String = array_username.iter()
            .map(|b| format!("{:02X}", b))
            .collect::<String>();

        assert_eq!(result, "73616d75656c72697a7a6f0000000000".to_uppercase());
    }

    #[test]
    fn test_encripted_username() {
        let mut array_username = hex::decode(convert_to_hex_string("TESTE")).expect("Decoding failed");
        let padding_required = 16 - array_username.len() % 16;
        if padding_required != 16 {
            array_username.extend(vec![0u8; padding_required]);
        }

        let padded_username = array_username.iter()
            .map(|b| format!("{:02X}", b))
            .collect::<String>();

        let username_hash = gunbound_static_encrypt(&hex::decode(padded_username).unwrap(), 1).unwrap();

        let result = username_hash.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();

        assert_eq!(result, "e4ae6422b374d8779dc2f3695810650f");
        
    }
}
