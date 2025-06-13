mod cipher;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn encrypt(password: &str, data: &str) -> String {
    match cipher::encrypt(password, data) {
        Ok(result) => result,
        Err(error) => {
            web_sys::console::error_1(&format!("Encryption error: {}", error).into());
            String::new()
        }
    }
}

#[wasm_bindgen]
pub fn decrypt(password: &str, data: &str) -> String {
    match cipher::decrypt(password, data) {
        Ok(result) => result,
        Err(error) => {
            web_sys::console::error_1(&format!("Decryption error: {}", error).into());
            String::new()
        }
    }
}
