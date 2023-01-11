use aes::Aes256;
use sha2::{Sha256, Digest};
use block_modes::{BlockMode, Cbc, block_padding::Pkcs7};


type AesCbc = Cbc<Aes256, Pkcs7>;
const SALT: &str = "LFsMH#kL!IfY:dcEz9F/dvj17nUN";

pub fn encrypt(password: &str, data: &str) -> String {
    let key = get_key(password);
    let iv = gen_iv();

    let cipher = AesCbc::new_from_slices (&key, &iv) .unwrap();
    let result = cipher.encrypt_vec(data.as_bytes());

    let mut ivres: Vec<u8> = vec![];
    ivres.extend(iv);
    ivres.extend(result);

    base64::encode(ivres)
}

fn gen_iv() -> Vec<u8> {
    let mut res: Vec<u8> = vec![0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0];
    getrandom::getrandom(&mut res).unwrap();
    res
}

fn get_key(password: &str) -> Vec<u8> {
    let pw: String = format!("{}:{}", password, SALT);
    let mut h = Sha256::new();
    h.update(pw.as_bytes());
    h.finalize().to_vec()
}

pub fn decrypt(password: &str, data: &str) -> String {
    let key = get_key(password);
    let bytes = base64::decode(data).unwrap();

    let iv = &bytes[..16];

    let cipher = AesCbc::new_from_slices(&key, iv).unwrap();
    let result = cipher.decrypt_vec(&bytes[16..]).unwrap();
    String::from_utf8(result).unwrap()
}


#[cfg(test)]
mod test_cipher {
    use super::*;
    #[test]
    fn test_enc_dec() {
        let password = "abcd";
        let data = "With great power comes great responsibility.";
        let enc = encrypt(password, data);
        println!("Encryption: {}", enc);
        let dec = decrypt(password, &enc);
        println!("Decryption: {}", dec);
        assert_eq!(data, dec);
    }
}
