use aes::Aes256;
use cbc::{Encryptor, Decryptor};
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use base64::{Engine as _, engine::general_purpose};

type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

const PBKDF2_ITERATIONS: u32 = 100_000;
const SALT_SIZE: usize = 16;
const IV_SIZE: usize = 16;
const KEY_SIZE: usize = 32;

pub fn encrypt(password: &str, data: &str) -> Result<String, String> {
    let salt = gen_salt()?;
    let key = derive_key(password, &salt)?;
    let iv = gen_iv()?;

    let cipher = Aes256CbcEnc::new(key.as_slice().try_into().map_err(|_| "Invalid key size")?, 
                                   iv.as_slice().try_into().map_err(|_| "Invalid IV size")?);
    
    // Create buffer with enough space for data + padding (up to one extra block)
    let data_bytes = data.as_bytes();
    let block_size = 16;
    let mut buffer = vec![0u8; data_bytes.len() + block_size];
    buffer[..data_bytes.len()].copy_from_slice(data_bytes);
    
    let ciphertext = cipher.encrypt_padded_mut::<Pkcs7>(&mut buffer, data_bytes.len())
        .map_err(|_| "Encryption failed")?;

    let mut result = Vec::new();
    result.extend_from_slice(&salt);
    result.extend_from_slice(&iv);
    result.extend_from_slice(ciphertext);

    Ok(general_purpose::STANDARD.encode(result))
}

fn gen_salt() -> Result<Vec<u8>, String> {
    let mut salt = vec![0u8; SALT_SIZE];
    getrandom::getrandom(&mut salt).map_err(|_| "Failed to generate salt")?;
    Ok(salt)
}

fn gen_iv() -> Result<Vec<u8>, String> {
    let mut iv = vec![0u8; IV_SIZE];
    getrandom::getrandom(&mut iv).map_err(|_| "Failed to generate IV")?;
    Ok(iv)
}

fn derive_key(password: &str, salt: &[u8]) -> Result<Vec<u8>, String> {
    let mut key = vec![0u8; KEY_SIZE];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, PBKDF2_ITERATIONS, &mut key);
    Ok(key)
}

pub fn decrypt(password: &str, data: &str) -> Result<String, String> {
    let bytes = general_purpose::STANDARD.decode(data)
        .map_err(|_| "Invalid base64 encoding")?;

    if bytes.len() < SALT_SIZE + IV_SIZE {
        return Err("Invalid ciphertext: too short".to_string());
    }

    let salt = &bytes[..SALT_SIZE];
    let iv = &bytes[SALT_SIZE..SALT_SIZE + IV_SIZE];
    let ciphertext = &bytes[SALT_SIZE + IV_SIZE..];

    let key = derive_key(password, salt)?;

    let cipher = Aes256CbcDec::new(key.as_slice().try_into().map_err(|_| "Invalid key size")?, 
                                   iv.try_into().map_err(|_| "Invalid IV size")?);
    let mut buffer = ciphertext.to_vec();
    
    let plaintext = cipher.decrypt_padded_mut::<Pkcs7>(&mut buffer)
        .map_err(|_| "Decryption failed - wrong password or corrupted data")?;

    String::from_utf8(plaintext.to_vec())
        .map_err(|_| "Invalid UTF-8 in decrypted data".to_string())
}


#[cfg(test)]
mod test_cipher {
    use super::*;
    
    #[test]
    fn test_enc_dec() {
        let password = "abcd";
        let data = "With great power comes great responsibility.";
        
        let enc = encrypt(password, data).expect("Encryption should succeed");
        println!("Encryption: {}", enc);
        
        let dec = decrypt(password, &enc).expect("Decryption should succeed");
        println!("Decryption: {}", dec);
        
        assert_eq!(data, dec);
    }

    #[test]
    fn test_wrong_password() {
        let password = "correct_password";
        let wrong_password = "wrong_password";
        let data = "Secret message";
        
        let enc = encrypt(password, data).expect("Encryption should succeed");
        let result = decrypt(wrong_password, &enc);
        
        assert!(result.is_err(), "Decryption with wrong password should fail");
    }

    #[test]
    fn test_invalid_base64() {
        let password = "password";
        let invalid_data = "invalid_base64!";
        
        let result = decrypt(password, invalid_data);
        assert!(result.is_err(), "Decryption of invalid base64 should fail");
    }
}
